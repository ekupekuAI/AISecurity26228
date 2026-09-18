"""Neural Cleanse: optimisation-based backdoor trigger inversion.

Wang et al. (IEEE S&P 2019) observed that a backdoored model needs a *much smaller*
perturbation to force every input into the backdoor's target class than into any other
class. That asymmetry is measurable without knowing the trigger.

For each candidate target class y we solve

    min_{m, d}  L( f( x*(1-m) + d*m ), y )  +  lambda * ||m||_1

over a batch of inputs x, where the mask m and pattern d are optimised jointly. The
recovered ||m||_1 is the size of the smallest universal perturbation that captures class
y. We then take the median absolute deviation across all classes and flag any class whose
L1 norm is anomalously *small*:

    anomaly_index = |L1 - median| / (1.4826 * MAD)

Wang et al. use an anomaly index above 2.0 as the detection threshold, which is the
default here.

Honest limitations, published with every result:
  * Assumes a small, static, input-agnostic trigger and a single target class.
  * An all-to-all backdoor shifts every class's L1 together, so the MAD comparison sees
    no outlier and the method reports nothing.
  * The inversion runs on synthetic imagery on an air-gapped node, which makes the
    absolute L1 values less meaningful than their relative ordering across classes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from core.config import SETTINGS
from modelscan.battery import build_reference_batch


@dataclass
class ClassInversion:
    class_index: int
    l1_norm: float
    l1_fraction: float
    final_loss: float
    attack_success: float
    anomaly_index: float = 0.0
    l1_ratio: float = 1.0
    flagged: bool = False
    mask_preview: list[list[float]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "classIndex": self.class_index,
            "l1Norm": round(self.l1_norm, 4),
            "l1Fraction": round(self.l1_fraction, 6),
            "finalLoss": round(self.final_loss, 5),
            "attackSuccessRate": round(self.attack_success, 4),
            "anomalyIndex": round(self.anomaly_index, 4),
            "l1RatioToMedian": round(self.l1_ratio, 4),
            "flagged": self.flagged,
            "maskPreview": self.mask_preview,
        }


@dataclass
class NeuralCleanseReport:
    ran: bool = False
    classes_scanned: int = 0
    classes_total: int = 0
    inversions: list[ClassInversion] = field(default_factory=list)
    median_l1: float = 0.0
    mad_l1: float = 0.0
    max_anomaly_index: float = 0.0
    flagged_classes: list[int] = field(default_factory=list)
    backdoor_confidence: float = 0.0
    suspected_family: str | None = None
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)
    limitation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran": self.ran,
            "classesScanned": self.classes_scanned,
            "classesTotal": self.classes_total,
            "inversions": [i.to_dict() for i in self.inversions],
            "medianL1": round(self.median_l1, 4),
            "madL1": round(self.mad_l1, 4),
            "maxAnomalyIndex": round(self.max_anomaly_index, 4),
            "flaggedClasses": self.flagged_classes,
            "backdoorConfidence": round(self.backdoor_confidence, 4),
            "suspectedFamily": self.suspected_family,
            "durationSeconds": round(self.duration_seconds, 2),
            "anomalyIndexThreshold": SETTINGS.thresholds.neural_cleanse_anomaly_index,
            "l1RatioThreshold": SETTINGS.thresholds.neural_cleanse_l1_ratio_max,
            "l1RatioDecisiveThreshold": SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive,
            "errors": self.errors,
            "limitation": self.limitation,
        }


def _invert_one_class(
    torch: Any,
    module: Any,
    batch: Any,
    target: int,
    channels: int,
    size: int,
    steps: int,
    lambda_l1: float,
) -> ClassInversion:
    """Optimise a mask and pattern that force `batch` into `target`."""
    # Determinism: the pattern is initialised randomly, so without a fixed seed the whole
    # inversion -- and therefore the flagged classes and backdoor confidence -- varies run to
    # run. "Reproducible integrity assessment" is a stated requirement, so the seed is fixed
    # per target class (independent of scan order) rather than left to the global RNG state.
    torch.manual_seed(0x5148 + int(target))

    # Both are parameterised through a sigmoid so they stay in range without clamping,
    # which keeps the gradient well-behaved.
    mask_logits = torch.zeros((1, 1, size, size), requires_grad=True)
    pattern_logits = torch.zeros((1, channels, size, size), requires_grad=True)

    with torch.no_grad():
        mask_logits.fill_(-3.0)  # start mostly transparent
        pattern_logits.uniform_(-0.1, 0.1)

    optimizer = torch.optim.Adam([mask_logits, pattern_logits], lr=0.1, betas=(0.5, 0.9))
    labels = torch.full((batch.shape[0],), target, dtype=torch.long)
    criterion = torch.nn.CrossEntropyLoss()

    final_loss = 0.0
    best_l1 = float("inf")
    best_mask: Any = None
    success = 0.0

    for step in range(steps):
        optimizer.zero_grad(set_to_none=True)
        mask = torch.sigmoid(mask_logits)
        pattern = torch.sigmoid(pattern_logits)
        stamped = batch * (1.0 - mask) + pattern * mask

        logits = module(stamped)
        if isinstance(logits, (tuple, list)):
            logits = logits[0]
        ce = criterion(logits.float(), labels)
        l1 = mask.abs().sum()
        loss = ce + lambda_l1 * l1
        loss.backward()
        optimizer.step()

        if step % 10 == 0 or step == steps - 1:
            with torch.no_grad():
                current_l1 = float(l1.item())
                predicted = logits.argmax(dim=1)
                rate = float((predicted == labels).float().mean().item())
                # Only accept a smaller mask once it actually captures the class; an
                # unconverged tiny mask is not a trigger.
                if rate >= 0.9 and current_l1 < best_l1:
                    best_l1 = current_l1
                    best_mask = mask.detach().clone()
                success = max(success, rate)
                final_loss = float(loss.item())

    with torch.no_grad():
        mask = torch.sigmoid(mask_logits)
        if best_mask is None:
            best_mask = mask.detach().clone()
            best_l1 = float(mask.abs().sum().item())

        preview_tensor = torch.nn.functional.interpolate(
            best_mask, size=(16, 16), mode="bilinear", align_corners=False
        )
        preview = [[round(float(v), 3) for v in row] for row in preview_tensor[0, 0].cpu().numpy()]

    return ClassInversion(
        class_index=target,
        l1_norm=best_l1,
        l1_fraction=best_l1 / float(size * size),
        final_loss=final_loss,
        attack_success=success,
        mask_preview=preview,
    )


def run(
    module: Any,
    class_count: int,
    channels: int,
    size: int,
    *,
    max_classes: int = 16,
    steps: int = 140,
    batch_size: int = 16,
) -> NeuralCleanseReport:
    """Invert a trigger for every candidate class and score the MAD anomaly index."""
    report = NeuralCleanseReport(classes_total=class_count)
    started = time.perf_counter()

    if class_count < 2:
        report.limitation = "Trigger inversion requires at least two output classes."
        return report

    try:
        import torch
    except Exception as exc:  # noqa: BLE001
        report.errors.append(f"PyTorch unavailable: {type(exc).__name__}")
        return report

    torch.set_num_threads(max(1, SETTINGS.torch_threads))

    reference = build_reference_batch(batch_size, channels, size)
    batch = torch.from_numpy(reference)

    # The parameters are frozen; only the mask and pattern carry gradients.
    for parameter in module.parameters():
        parameter.requires_grad_(False)

    # A large class count would make this unbounded, so we scan a prefix and say so.
    scan_count = min(class_count, max_classes)
    lambda_l1 = 0.01 / float(size * size) * 100.0

    deadline = started + SETTINGS.limits.neural_cleanse_timeout_seconds

    for target in range(scan_count):
        if time.perf_counter() > deadline:
            report.errors.append(
                f"Trigger inversion stopped after {target} of {scan_count} classes: the "
                f"{SETTINGS.limits.neural_cleanse_timeout_seconds}s budget was exhausted."
            )
            break
        try:
            inversion = _invert_one_class(torch, module, batch, target, channels, size, steps, lambda_l1)
            report.inversions.append(inversion)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"Class {target} inversion failed: {type(exc).__name__}: {exc}")

    report.classes_scanned = len(report.inversions)
    report.duration_seconds = time.perf_counter() - started

    if report.classes_scanned < 3:
        report.limitation = (
            "Fewer than three classes were successfully inverted, which is too few for the "
            "median-absolute-deviation comparison Neural Cleanse relies on. No backdoor "
            "conclusion is drawn."
        )
        return report

    report.ran = True
    norms = np.array([i.l1_norm for i in report.inversions], dtype=np.float64)
    median = float(np.median(norms))
    mad = float(np.median(np.abs(norms - median)))
    consistent_mad = 1.4826 * mad  # scale MAD to a standard-deviation equivalent
    report.median_l1 = median
    report.mad_l1 = mad

    threshold = SETTINGS.thresholds.neural_cleanse_anomaly_index

    for inversion in report.inversions:
        if consistent_mad <= 1e-9:
            inversion.anomaly_index = 0.0
        else:
            inversion.anomaly_index = abs(inversion.l1_norm - median) / consistent_mad
        # Three conditions, all required. Only a class that is anomalously *small* is a
        # backdoor candidate -- a class that is unusually hard to reach is the opposite of
        # a shortcut -- and the mask must be dramatically smaller than the median rather
        # than merely MAD-anomalous, because the index alone false-positives on clean
        # models at this step budget.
        inversion.l1_ratio = inversion.l1_norm / median if median > 0 else 1.0

        # The inversion must have actually converged on the class before any of this
        # means anything.
        converged = inversion.attack_success >= 0.85
        decisive = inversion.l1_ratio <= SETTINGS.thresholds.neural_cleanse_l1_ratio_decisive
        corroborated = (
            inversion.anomaly_index > threshold
            and inversion.l1_ratio <= SETTINGS.thresholds.neural_cleanse_l1_ratio_max
        )
        inversion.flagged = converged and (decisive or corroborated)

    report.max_anomaly_index = max((i.anomaly_index for i in report.inversions if i.l1_norm < median), default=0.0)
    report.flagged_classes = [i.class_index for i in report.inversions if i.flagged]

    if report.flagged_classes:
        flagged = [i for i in report.inversions if i.flagged]
        strongest = min(flagged, key=lambda i: i.l1_norm)
        # Confidence rises with how far past the threshold the anomaly index sits and how
        # small the recovered trigger is relative to the frame.
        index_component = min(1.0, (strongest.anomaly_index - threshold) / 3.0)
        size_component = min(1.0, max(0.0, (SETTINGS.thresholds.neural_cleanse_l1_fraction - strongest.l1_fraction) / SETTINGS.thresholds.neural_cleanse_l1_fraction))
        report.backdoor_confidence = float(min(0.95, 0.5 + 0.3 * index_component + 0.2 * size_component))
        report.suspected_family = (
            "BadNets / localised patch trigger"
            if strongest.l1_fraction < 0.03
            else "Blended or medium-extent trigger"
        )

    report.limitation = (
        "Neural Cleanse assumes a small, static, input-agnostic trigger and a single target "
        "class. All-to-all backdoors shift every class's L1 norm together and produce no MAD "
        "outlier; input-aware families such as WaNet and BppAttack are outside its model "
        "entirely. Inversion ran against a deterministic synthetic batch because this node holds "
        "no operational data, so the relative ordering of L1 norms across classes is meaningful "
        "while their absolute magnitudes are not calibrated."
    )
    if report.classes_scanned < class_count:
        report.limitation += (
            f" Only {report.classes_scanned} of {class_count} classes were scanned within the time "
            "budget; an unscanned class could still host a backdoor."
        )

    return report


__all__ = ["ClassInversion", "NeuralCleanseReport", "run"]
