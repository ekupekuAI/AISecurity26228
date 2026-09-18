"""Shared result vocabulary for every analytical engine.

The wire contract is camelCase because the React console and the Node gateway consume
it directly. Building findings through `make_finding` rather than dict literals keeps
the schema honest: every finding must carry evidence and a recommendation, and every
detector must declare the threshold that fired.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Category = Literal["DATASET", "MODEL", "INFERENCE", "DISTRIBUTION", "PROVENANCE", "SUPPLY_CHAIN"]
AssuranceStatus = Literal[
    "DETECTED", "SUSPICIOUS", "NOT DETECTED", "NOT SUPPORTED", "ANALYSIS FAILED"
]
Decision = Literal["ACCEPT", "REVIEW", "QUARANTINE"]

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


class AnalysisMode(str, Enum):
    """How much access the engine actually had to the asset.

    The problem statement explicitly requires documenting access assumptions, so the
    mode is attached to every model assessment rather than inferred by the reader.
    """

    WHITE_BOX = "WHITE_BOX"  # weights loaded, forward passes executed
    GREY_BOX = "GREY_BOX"  # structure parsed, no execution
    BLACK_BOX = "BLACK_BOX"  # hash and container only
    REFUSED = "REFUSED"  # unsafe to inspect further


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def make_finding(
    *,
    finding_id: str,
    category: Category,
    severity: Severity,
    confidence: float,
    affected_asset: str,
    explanation: str,
    evidence: Any,
    recommendation: str,
    detector: str,
    threshold: str | None = None,
    references: list[str] | None = None,
) -> dict[str, Any]:
    """Build one finding.

    `detector` and `threshold` are what make a result reproducible: a reviewer can read
    the finding and know exactly which routine fired and at what cut-off, without
    reading the source.
    """
    return {
        "id": new_id("FIND"),
        "findingId": finding_id,
        "category": category,
        "severity": severity,
        "confidence": round(float(max(0.0, min(1.0, confidence))), 4),
        "affectedAsset": affected_asset,
        "explanation": explanation,
        "evidence": evidence,
        "recommendation": recommendation,
        "detector": detector,
        "threshold": threshold,
        "references": references or [],
        "timestamp": utc_now(),
    }


def status_from_findings(findings: list[dict[str, Any]]) -> AssuranceStatus:
    """Collapse a finding list into the console's four-state status."""
    if any(f.get("severity") == "CRITICAL" for f in findings):
        return "DETECTED"
    if any(f.get("severity") == "HIGH" for f in findings):
        return "DETECTED"
    if any(f.get("severity") == "MEDIUM" for f in findings):
        return "SUSPICIOUS"
    return "NOT DETECTED"


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "INFO"), 9), -float(f.get("confidence", 0))),
    )


@dataclass
class CoverageEntry:
    """One row of the attack-coverage matrix.

    `covered` is deliberately tri-state via `confidence`: a detector can be present but
    degraded (for example embedding checks running on an un-provisioned backbone), and
    a reviewer needs to see that rather than a bare tick.
    """

    threat: str
    technique: str
    covered: bool
    confidence: float
    method: str
    limitation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat": self.threat,
            "technique": self.technique,
            "covered": self.covered,
            "confidence": round(self.confidence, 3),
            "method": self.method,
            "limitation": self.limitation,
            "references": self.references,
        }


__all__ = [
    "AnalysisMode",
    "AssuranceStatus",
    "Category",
    "CoverageEntry",
    "Decision",
    "SEVERITY_ORDER",
    "Severity",
    "make_finding",
    "new_id",
    "sort_findings",
    "status_from_findings",
    "utc_now",
]
