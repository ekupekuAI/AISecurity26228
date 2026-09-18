"""Label-flipping and systematic mislabelling detection via clean-feature k-NN.

The attack: a contributor flips labels on a targeted subset -- military_vehicle
annotated as civilian_vehicle -- so the trained model reliably misses that class in the
field. Random annotation error looks like scattered single samples; an attack looks like
a *directed* flow between one specific class pair.

The detector is a k-NN cross-validation in embedding space, the practical core of
confident learning (Northcutt et al., 2021). For each sample we look at its k nearest
neighbours among the *other* samples and ask how much of that neighbourhood disagrees
with the declared label. A sample deep inside another class's cluster is the signature
of a flip, and the aggregate flow between class pairs is what separates deliberate
manipulation from ordinary annotation noise.

This is the analysis that most needs real pretrained features, so its confidence is
scaled by the backbone's own confidence multiplier.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

from core.config import SETTINGS


@dataclass
class SuspectLabel:
    path: str
    declared_label: str
    projected_label: str
    disagreement: float
    margin: float
    neighbour_distribution: dict[str, float]
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "declaredLabel": self.declared_label,
            "projectedLabel": self.projected_label,
            "neighbourDisagreement": round(self.disagreement, 4),
            "margin": round(self.margin, 4),
            "neighbourDistribution": {k: round(v, 4) for k, v in self.neighbour_distribution.items()},
            "confidence": round(self.confidence, 4),
        }


@dataclass
class ClassPairFlow:
    """Directed mass of suspected flips from one class to another."""

    from_label: str
    to_label: str
    count: int
    share_of_source: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "fromLabel": self.from_label,
            "toLabel": self.to_label,
            "count": self.count,
            "shareOfSourceClass": round(self.share_of_source, 4),
        }


@dataclass
class LabelNoiseReport:
    analysed: int = 0
    suspects: list[SuspectLabel] = field(default_factory=list)
    class_pair_flows: list[ClassPairFlow] = field(default_factory=list)
    systematic: bool = False
    systematic_explanation: str = ""
    noise_rate: float = 0.0
    per_class_noise: dict[str, float] = field(default_factory=dict)
    available: bool = False
    limitation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "analysedSamples": self.analysed,
            "suspectCount": len(self.suspects),
            "suspects": [s.to_dict() for s in self.suspects[:60]],
            "classPairFlows": [f.to_dict() for f in self.class_pair_flows[:20]],
            "systematicManipulation": self.systematic,
            "systematicExplanation": self.systematic_explanation,
            "estimatedNoiseRate": round(self.noise_rate, 4),
            "perClassNoiseRate": {k: round(v, 4) for k, v in self.per_class_noise.items()},
            "limitation": self.limitation,
        }


def detect_label_noise(
    embeddings: np.ndarray,
    labels: Sequence[str],
    paths: Sequence[str],
    backbone_confidence: float = 1.0,
) -> LabelNoiseReport:
    """Flag samples whose embedding neighbourhood contradicts their declared label."""
    thresholds = SETTINGS.thresholds
    report = LabelNoiseReport()

    unique_labels = sorted(set(labels))
    if embeddings.size == 0 or len(labels) < 2 * thresholds.knn_neighbours or len(unique_labels) < 2:
        report.limitation = (
            "Label-consistency cross-validation needs at least two labelled classes and "
            f"{2 * thresholds.knn_neighbours} embedded samples. The corpus supplied "
            f"{len(labels)} samples across {len(unique_labels)} class(es), so the check was "
            "not run. This is a coverage gap, not a clean result."
        )
        return report

    # Drop classes too small to have a meaningful neighbourhood; a 3-sample class would
    # otherwise be flagged wholesale.
    counts = Counter(labels)
    viable = {label for label, n in counts.items() if n >= thresholds.knn_neighbours // 2}
    if len(viable) < 2:
        report.limitation = (
            "No two classes carry enough samples to support k-NN cross-validation "
            f"(minimum {thresholds.knn_neighbours // 2} per class)."
        )
        return report

    mask = np.array([label in viable for label in labels], dtype=bool)
    features = embeddings[mask]
    subset_labels = [label for label, keep in zip(labels, mask) if keep]
    subset_paths = [path for path, keep in zip(paths, mask) if keep]

    report.available = True
    report.analysed = len(subset_labels)
    k = min(thresholds.knn_neighbours, len(subset_labels) - 1)

    # Features are L2-normalised, so the inner product is cosine similarity and ranking
    # by it is equivalent to ranking by Euclidean distance.
    similarity = features @ features.T
    np.fill_diagonal(similarity, -np.inf)
    neighbour_idx = np.argpartition(-similarity, kth=k - 1, axis=1)[:, :k]

    label_array = np.array(subset_labels)
    suspects: list[SuspectLabel] = []
    flows: dict[tuple[str, str], int] = defaultdict(int)
    per_class_flagged: dict[str, int] = defaultdict(int)

    for row in range(len(subset_labels)):
        declared = subset_labels[row]
        neighbour_labels = label_array[neighbour_idx[row]]
        distribution = Counter(neighbour_labels.tolist())
        total = float(len(neighbour_labels))

        own_share = distribution.get(declared, 0) / total
        disagreement = 1.0 - own_share

        projected, projected_count = distribution.most_common(1)[0]
        projected_share = projected_count / total
        margin = projected_share - own_share

        if (
            disagreement >= thresholds.label_disagreement_min
            and margin >= thresholds.label_margin_min
            and projected != declared
        ):
            # Confidence blends how lopsided the neighbourhood is with how much we trust
            # the backbone that produced it.
            raw_confidence = min(0.99, 0.5 + 0.5 * margin + 0.2 * (disagreement - thresholds.label_disagreement_min))
            suspects.append(
                SuspectLabel(
                    path=subset_paths[row],
                    declared_label=declared,
                    projected_label=str(projected),
                    disagreement=disagreement,
                    margin=margin,
                    neighbour_distribution={str(k_): v / total for k_, v in distribution.items()},
                    confidence=raw_confidence * backbone_confidence,
                )
            )
            flows[(declared, str(projected))] += 1
            per_class_flagged[declared] += 1

    suspects.sort(key=lambda s: (-s.margin, -s.disagreement))
    report.suspects = suspects
    report.noise_rate = len(suspects) / max(1, len(subset_labels))
    report.per_class_noise = {
        label: per_class_flagged.get(label, 0) / counts[label] for label in sorted(viable)
    }

    for (source, target), count in sorted(flows.items(), key=lambda kv: kv[1], reverse=True):
        report.class_pair_flows.append(
            ClassPairFlow(
                from_label=source,
                to_label=target,
                count=count,
                share_of_source=count / max(1, counts[source]),
            )
        )

    report.systematic, report.systematic_explanation = _assess_systematic(report, counts)

    if backbone_confidence < 1.0:
        report.limitation = (
            "Label-consistency results were produced without a pretrained backbone. "
            "Reported confidences are scaled down accordingly and this check should be "
            "re-run once reference weights are staged."
        )
    return report


def _assess_systematic(report: LabelNoiseReport, counts: Counter) -> tuple[bool, str]:
    """Separate deliberate, directed flipping from diffuse annotation error.

    Random error spreads a class's mistakes across every other class roughly in
    proportion to class sizes. A targeted attack concentrates them into one destination,
    so a single dominant flow that also covers a material share of the source class is
    the signal we act on.
    """
    if not report.class_pair_flows:
        return False, "No directed label flow detected above threshold."

    top = report.class_pair_flows[0]
    total_flagged = sum(flow.count for flow in report.class_pair_flows)
    concentration = top.count / max(1, total_flagged)

    if top.count >= 8 and concentration >= 0.6 and top.share_of_source >= 0.03:
        return True, (
            f"{top.count} samples flow from '{top.from_label}' to '{top.to_label}', "
            f"{concentration:.0%} of all flagged samples and {top.share_of_source:.1%} of the "
            "source class. A single dominant direction at this concentration is characteristic "
            "of targeted label flipping rather than diffuse annotation error, which spreads "
            "across destination classes in proportion to class size."
        )

    return False, (
        f"Flagged samples are distributed across {len(report.class_pair_flows)} class pairs with "
        f"the largest accounting for {concentration:.0%}. The pattern is consistent with ordinary "
        "annotation noise rather than directed manipulation."
    )


__all__ = ["ClassPairFlow", "LabelNoiseReport", "SuspectLabel", "detect_label_noise"]
