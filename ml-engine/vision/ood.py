"""Out-of-distribution scoring via Mahalanobis distance to class centroids.

An OOD sample is one the model will be asked to classify but was never trained to
handle -- a night-vision frame in a daylight corpus, a different sensor, or simply
imagery from an unrelated domain that a contributor padded their submission with. In a
defence pipeline these are blind spots rather than mere noise.

Following Lee et al. (2018), each class is modelled as a Gaussian in feature space and a
sample is scored by its Mahalanobis distance to the nearest class centroid, using a
shared covariance pooled across classes. Two departures from the paper matter here:

* **Ledoit-Wolf shrinkage** on the covariance. With 512-d features and a few hundred
  samples the empirical covariance is singular, so the textbook inverse is numerically
  meaningless. Shrinkage toward a scaled identity keeps it conditioned.
* **Empirical percentile thresholds** rather than a fixed cut-off. We have no
  calibration set on an air-gapped node, so "outlier" is defined relative to the corpus
  under inspection. That is stated in the limitation rather than hidden.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

from core.config import SETTINGS


@dataclass
class OODSample:
    path: str
    label: str
    distance: float
    percentile: float
    nearest_class: str
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "label": self.label,
            "mahalanobisDistance": round(self.distance, 4),
            "corpusPercentile": round(self.percentile, 3),
            "nearestClass": self.nearest_class,
            "anomalyScore": round(self.score, 4),
        }


@dataclass
class OODReport:
    available: bool = False
    analysed: int = 0
    outliers: list[OODSample] = field(default_factory=list)
    threshold_distance: float = 0.0
    median_distance: float = 0.0
    per_class_outliers: dict[str, int] = field(default_factory=dict)
    covariance_condition: float = 0.0
    limitation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "analysedSamples": self.analysed,
            "outlierCount": len(self.outliers),
            "outliers": [o.to_dict() for o in self.outliers[:60]],
            "thresholdDistance": round(self.threshold_distance, 4),
            "medianDistance": round(self.median_distance, 4),
            "perClassOutliers": self.per_class_outliers,
            "covarianceCondition": round(self.covariance_condition, 2),
            "limitation": self.limitation,
        }


def _shrunk_precision(centred: np.ndarray) -> tuple[np.ndarray, float]:
    """Ledoit-Wolf shrunk precision matrix and the condition number after shrinkage."""
    n, d = centred.shape
    if n < 2:
        return np.eye(d, dtype=np.float32), 1.0

    empirical = (centred.T @ centred) / max(1, n - 1)
    mu = float(np.trace(empirical) / d)
    target = mu * np.eye(d, dtype=np.float32)

    # Ledoit-Wolf optimal shrinkage intensity. The beta term is
    # (1/n^2) * sum_i ||x_i x_i^T - S||_F^2 / d, expanded so we never materialise an
    # outer product per sample -- that would be O(n*d^2) and is the difference between
    # seconds and minutes on a 512-d, few-thousand-sample corpus.
    delta = float(((empirical - target) ** 2).sum() / d)
    sq_norms = np.einsum("nd,nd->n", centred, centred)
    quad = np.einsum("nd,de,ne->n", centred, empirical, centred)
    beta_sum = float((sq_norms**2).sum() - 2.0 * quad.sum() + n * float((empirical**2).sum()))
    beta = min(delta, beta_sum / (d * n**2))
    shrinkage = 0.0 if delta <= 0 else float(np.clip(beta / delta, 0.0, 1.0))

    shrunk = (1.0 - shrinkage) * empirical + shrinkage * target
    # Final ridge keeps the inverse finite even for a degenerate corpus.
    shrunk += np.eye(d, dtype=np.float32) * 1e-6

    try:
        precision = np.linalg.inv(shrunk)
        condition = float(np.linalg.cond(shrunk))
    except np.linalg.LinAlgError:
        precision = np.linalg.pinv(shrunk)
        condition = float("inf")

    return precision.astype(np.float32), condition


def detect_ood(
    embeddings: np.ndarray,
    labels: Sequence[str],
    paths: Sequence[str],
    backbone_confidence: float = 1.0,
) -> OODReport:
    """Rank samples by Mahalanobis distance to their nearest class centroid."""
    thresholds = SETTINGS.thresholds
    report = OODReport()

    if embeddings.size == 0 or len(paths) < 2 * thresholds.ood_min_class_samples:
        report.limitation = (
            "Mahalanobis OOD scoring needs at least "
            f"{2 * thresholds.ood_min_class_samples} embedded samples to estimate a "
            f"covariance; {len(paths)} were available. The check did not run."
        )
        return report

    counts = Counter(labels)
    viable = {label for label, n in counts.items() if n >= thresholds.ood_min_class_samples}
    if not viable:
        # Fall back to a single global Gaussian: still useful for spotting samples that
        # do not belong to the corpus at all, even without usable class structure.
        viable = {"__corpus__"}
        working_labels = ["__corpus__"] * len(labels)
    else:
        working_labels = list(labels)

    mask = np.array([label in viable for label in working_labels], dtype=bool)
    if mask.sum() < thresholds.ood_min_class_samples:
        report.limitation = "No class carried enough samples to model a distribution."
        return report

    features = embeddings[mask].astype(np.float32)
    subset_labels = [label for label, keep in zip(working_labels, mask) if keep]
    subset_paths = [path for path, keep in zip(paths, mask) if keep]
    original_labels = [label for label, keep in zip(labels, mask) if keep]

    class_names = sorted(set(subset_labels))
    centroids: dict[str, np.ndarray] = {}
    centred_parts: list[np.ndarray] = []

    for name in class_names:
        rows = features[[i for i, label in enumerate(subset_labels) if label == name]]
        centroid = rows.mean(axis=0)
        centroids[name] = centroid
        centred_parts.append(rows - centroid)

    centred = np.concatenate(centred_parts, axis=0)
    precision, condition = _shrunk_precision(centred)
    report.covariance_condition = condition

    centroid_matrix = np.stack([centroids[name] for name in class_names])

    # Vectorised Mahalanobis, expanded as x'Px - 2x'Pmu + mu'Pmu so we never build the
    # [n, classes, dim] difference tensor.
    projected = features @ precision  # [n, d]
    self_term = np.einsum("nd,nd->n", projected, features)  # [n]
    cross_term = projected @ centroid_matrix.T  # [n, c]
    centroid_term = np.einsum("cd,de,ce->c", centroid_matrix, precision, centroid_matrix)  # [c]
    sq_distances = self_term[:, None] - 2.0 * cross_term + centroid_term[None, :]
    sq_distances = np.maximum(sq_distances, 0.0)
    distances = np.sqrt(sq_distances)

    nearest = distances.argmin(axis=1)
    min_distance = distances.min(axis=1)

    report.available = True
    report.analysed = len(subset_paths)
    report.median_distance = float(np.median(min_distance))
    threshold = float(np.percentile(min_distance, thresholds.ood_mahalanobis_percentile))
    report.threshold_distance = threshold

    ranks = min_distance.argsort().argsort() / max(1, len(min_distance) - 1)
    spread = float(min_distance.max() - report.median_distance) or 1.0

    per_class: Counter = Counter()
    for i, distance in enumerate(min_distance):
        if distance < threshold:
            continue
        score = float(np.clip((distance - report.median_distance) / spread, 0.0, 1.0))
        per_class[original_labels[i]] += 1
        report.outliers.append(
            OODSample(
                path=subset_paths[i],
                label=original_labels[i],
                distance=float(distance),
                percentile=float(ranks[i] * 100.0),
                nearest_class=class_names[int(nearest[i])],
                score=score * backbone_confidence,
            )
        )

    report.outliers.sort(key=lambda o: -o.distance)
    report.per_class_outliers = dict(per_class)

    report.limitation = (
        "Outliers are defined relative to the submitted corpus at the "
        f"{thresholds.ood_mahalanobis_percentile:.0f}th percentile of Mahalanobis distance, "
        "not against an external reference distribution. A corpus that is uniformly "
        "out-of-domain will therefore report few internal outliers; cross-corpus drift is "
        "the distribution-shift engine's responsibility, not this detector's."
    )
    if condition > 1e8:
        report.limitation += (
            f" The pooled covariance is ill-conditioned (cond={condition:.1e}); distances "
            "should be read as ordinal rankings rather than calibrated magnitudes."
        )
    if backbone_confidence < 1.0:
        report.limitation += " Scores are scaled down because no pretrained backbone was staged."

    return report


__all__ = ["OODReport", "OODSample", "detect_ood"]
