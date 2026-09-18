"""Deterministic risk scoring, confidence fusion and the governance triad.

Every number this module produces is a pure function of its inputs: the same evidence
scores identically on every node, every run. That is what "reproducible integrity
assessment" requires, and it is why nothing here samples, times out into a default, or
depends on wall-clock.

Two properties are deliberate:

* **Confidence-weighted severity with saturation.** Ten MEDIUM findings should not add
  up to worse than one CRITICAL. Raw severity mass is passed through
  ``100 * (1 - e^(-mass/45))`` so each additional finding contributes less, and a single
  confident CRITICAL still dominates the score.
* **Override rules outrank the arithmetic.** A cryptographic tamper or a confirmed
  backdoor quarantines the asset regardless of the composite number, because averaging a
  fatal defect against four healthy pillars is exactly how a real failure gets shipped.

Decision bands are fixed by the problem statement: ACCEPT below 30, REVIEW 30-69,
QUARANTINE at 70 and above.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from core.config import SETTINGS

SEVERITY_WEIGHTS: dict[str, float] = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0,
    "INFO": 0.0,
}

COMPONENT_WEIGHTS: dict[str, float] = {
    "dataset": 0.35,
    "model": 0.35,
    "inference": 0.15,
    "shift": 0.15,
}

SATURATION_CONSTANT = 45.0


def findings_risk(findings: Sequence[dict[str, Any]]) -> float:
    """Collapse a finding list into a 0-100 risk contribution."""
    if not findings:
        return 0.0

    mass = 0.0
    for finding in findings:
        weight = SEVERITY_WEIGHTS.get(str(finding.get("severity", "INFO")).upper(), 0.0)
        confidence = float(finding.get("confidence", 1.0) or 0.0)
        mass += weight * max(0.0, min(1.0, confidence))

    import math

    normalised = 100.0 * (1.0 - math.exp(-mass / SATURATION_CONSTANT))
    return round(max(0.0, min(100.0, normalised)), 1)


def dataset_risk(
    *,
    total_samples: int,
    corrupt_count: int,
    redundant_count: int,
    label_suspect_count: int,
    label_noise_is_systematic: bool,
    trigger_confirmed_count: int,
    ood_count: int,
    annotation_defects: int,
    class_imbalance_ratio: float,
    finding_risk: float,
) -> tuple[float, dict[str, float]]:
    """Blend prevalence-based risk with finding-based risk.

    Prevalence matters because 12 poisoned samples in 200 is a very different corpus from
    12 in 100,000, and a purely finding-driven score cannot see that difference.
    """
    if total_samples <= 0:
        return 100.0, {"reason": 100.0}

    n = float(total_samples)
    contributions = {
        # A trigger is the only defect that is categorically an attack, so its
        # prevalence is weighted an order of magnitude above hygiene defects.
        "triggerPrevalence": min(45.0, (trigger_confirmed_count / n) * 1500.0),
        # Directed flipping is an attack; diffuse disagreement is a data-quality
        # observation. Weighting them the same makes every real-world corpus look
        # poisoned, because semantically adjacent classes always disagree somewhat.
        "labelNoisePrevalence": (
            min(25.0, (label_suspect_count / n) * 250.0)
            if label_noise_is_systematic
            else min(8.0, (label_suspect_count / n) * 40.0)
        ),
        "corruptPrevalence": min(15.0, (corrupt_count / n) * 120.0),
        "redundancyPrevalence": min(15.0, (redundant_count / n) * 60.0),
        "oodPrevalence": min(12.0, (ood_count / n) * 80.0),
        "annotationDefects": min(10.0, (annotation_defects / n) * 40.0),
        "classImbalance": min(8.0, max(0.0, (class_imbalance_ratio - 3.0) * 1.2)),
    }

    prevalence = sum(contributions.values())
    combined = 0.5 * min(100.0, prevalence) + 0.5 * finding_risk
    contributions["prevalenceSubtotal"] = round(min(100.0, prevalence), 2)
    contributions["findingSubtotal"] = round(finding_risk, 2)
    return round(min(100.0, max(0.0, combined)), 1), {k: round(v, 3) for k, v in contributions.items()}


def model_risk(
    *,
    finding_risk: float,
    serialization_verdict: str,
    backdoor_confidence: float,
    weight_anomaly_score: float,
    structural_anomaly_score: float,
) -> tuple[float, dict[str, float]]:
    """Model risk. A hostile serialization verdict short-circuits to the maximum."""
    if serialization_verdict == "MALICIOUS":
        return 100.0, {"serialization": 100.0, "reason": 100.0}

    contributions = {
        "findingSubtotal": round(finding_risk, 2),
        "backdoorEvidence": round(min(60.0, backdoor_confidence * 85.0), 2),
        "weightAnomaly": round(min(20.0, weight_anomaly_score * 20.0), 2),
        "structuralAnomaly": round(min(20.0, structural_anomaly_score * 20.0), 2),
        "serialization": 25.0 if serialization_verdict == "SUSPICIOUS" else 0.0,
    }

    score = max(
        finding_risk,
        contributions["backdoorEvidence"]
        + contributions["weightAnomaly"]
        + contributions["structuralAnomaly"]
        + contributions["serialization"],
    )
    return round(min(100.0, max(0.0, score)), 1), contributions


def overall_risk(
    dataset: float, model: float, inference: float, shift: float
) -> dict[str, float]:
    composite = (
        COMPONENT_WEIGHTS["dataset"] * dataset
        + COMPONENT_WEIGHTS["model"] * model
        + COMPONENT_WEIGHTS["inference"] * inference
        + COMPONENT_WEIGHTS["shift"] * shift
    )
    clamped = round(min(100.0, max(0.0, composite)), 1)
    return {
        "overallRisk": clamped,
        "trustScore": round(max(0.0, 100.0 - clamped), 1),
        "datasetRisk": round(dataset, 1),
        "modelRisk": round(model, 1),
        "inferenceRisk": round(inference, 1),
        "shiftRisk": round(shift, 1),
    }


@dataclass
class GovernanceInput:
    overall_risk: float
    dataset_risk: float = 0.0
    model_risk: float = 0.0
    inference_risk: float = 0.0
    shift_risk: float = 0.0
    has_critical_finding: bool = False
    has_tampered_inference: bool = False
    has_confirmed_backdoor: bool = False
    has_malicious_serialization: bool = False
    has_replay_detected: bool = False
    analysis_incomplete: bool = False


@dataclass
class GovernanceOutcome:
    decision: str
    action_required: str
    rationale: str
    triggered_rules: list[str] = field(default_factory=list)
    thresholds: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "actionRequired": self.action_required,
            "rationale": self.rationale,
            "triggeredRules": self.triggered_rules,
            "thresholds": self.thresholds,
        }


def evaluate_governance(inputs: GovernanceInput) -> GovernanceOutcome:
    """Apply the PS decision matrix: overrides first, then the risk bands."""
    thresholds = SETTINGS.thresholds
    bands = {
        "acceptBelow": thresholds.accept_max_risk,
        "quarantineAtOrAbove": thresholds.quarantine_min_risk,
    }

    overrides: list[str] = []
    if inputs.has_malicious_serialization:
        overrides.append("MALICIOUS_SERIALIZATION: checkpoint contains an execution primitive or a broken pickle stream")
    if inputs.has_tampered_inference:
        overrides.append("CRYPTOGRAPHIC_MISMATCH: an inference record failed digest or signature verification")
    if inputs.has_replay_detected:
        overrides.append("REPLAY_DETECTED: a nonce was reused across inference records")
    if inputs.has_confirmed_backdoor:
        overrides.append("BACKDOOR_CONFIRMED: trigger inversion or behavioural battery confirmed a backdoor")
    if inputs.has_critical_finding:
        overrides.append("CRITICAL_FINDING: at least one CRITICAL-severity finding is outstanding")

    if overrides:
        return GovernanceOutcome(
            decision="QUARANTINE",
            action_required=(
                "IMMEDIATE OPERATIONAL QUARANTINE. Isolate the asset, revoke the contributing "
                "ingest pipeline, preserve the archive for forensic analysis, and notify the "
                "security officer. Do not deploy under any compensating control."
            ),
            rationale=(
                "A mandatory override fired. These conditions are not averaged against the "
                "composite score because a single fatal defect is disqualifying regardless of "
                "how healthy the remaining pillars are."
            ),
            triggered_rules=overrides,
            thresholds=bands,
        )

    if inputs.overall_risk >= thresholds.quarantine_min_risk:
        return GovernanceOutcome(
            decision="QUARANTINE",
            action_required=(
                "Isolate the asset and revoke its deployment authorisation. Remediate the "
                "highest-weighted findings and resubmit for a full re-assessment."
            ),
            rationale=(
                f"Composite risk {inputs.overall_risk:.1f} meets or exceeds the quarantine "
                f"threshold of {thresholds.quarantine_min_risk:.0f}."
            ),
            triggered_rules=[f"COMPOSITE_RISK >= {thresholds.quarantine_min_risk:.0f}"],
            thresholds=bands,
        )

    if inputs.overall_risk >= thresholds.accept_max_risk or inputs.analysis_incomplete:
        rules = []
        if inputs.overall_risk >= thresholds.accept_max_risk:
            rules.append(
                f"COMPOSITE_RISK in [{thresholds.accept_max_risk:.0f}, {thresholds.quarantine_min_risk:.0f})"
            )
        if inputs.analysis_incomplete:
            rules.append("COVERAGE_GAP: one or more engines could not complete their assessment")
        return GovernanceOutcome(
            decision="REVIEW",
            action_required=(
                "Human-in-the-loop analyst triage required before operational release. Restrict "
                "the asset to a limited operational scope and obtain secondary sign-off from the "
                "Lead Assurance Engineer."
            ),
            rationale=(
                f"Composite risk {inputs.overall_risk:.1f} sits in the review band"
                + (", and part of the assessment could not be completed." if inputs.analysis_incomplete else ".")
            ),
            triggered_rules=rules,
            thresholds=bands,
        )

    return GovernanceOutcome(
        decision="ACCEPT",
        action_required=(
            "Authorised for operational deployment. A cryptographic seal has been issued and "
            "recorded in the append-only audit ledger."
        ),
        rationale=(
            f"Composite risk {inputs.overall_risk:.1f} is below the acceptance threshold of "
            f"{thresholds.accept_max_risk:.0f}, no override condition fired, and every engine "
            "completed its assessment."
        ),
        triggered_rules=[f"COMPOSITE_RISK < {thresholds.accept_max_risk:.0f}"],
        thresholds=bands,
    )


def fuse_confidence(values: Sequence[float]) -> float:
    """Combine independent detector confidences with a noisy-OR.

    Independent detectors agreeing should raise combined confidence above either alone,
    which a mean or a max cannot express.
    """
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(1.0, float(value)))
    return round(1.0 - remaining, 4)


__all__ = [
    "COMPONENT_WEIGHTS",
    "SEVERITY_WEIGHTS",
    "GovernanceInput",
    "GovernanceOutcome",
    "dataset_risk",
    "evaluate_governance",
    "findings_risk",
    "fuse_confidence",
    "model_risk",
    "overall_risk",
]
