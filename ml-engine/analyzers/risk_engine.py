"""
Deterministic Risk Engine
Implements weighted scoring for AI pipeline assets based on empirical findings.
All scores are deterministic and mathematically reproducible.
"""

from typing import List, Dict, Any

class RiskEngine:
    SEVERITY_WEIGHTS = {
        "CRITICAL": 25.0,
        "HIGH": 15.0,
        "MEDIUM": 8.0,
        "LOW": 3.0,
        "INFO": 0.0
    }

    # Component weights in overall system risk
    COMPONENT_WEIGHTS = {
        "dataset": 0.35,
        "model": 0.35,
        "inference": 0.15,
        "shift": 0.15
    }

    @classmethod
    def calculate_findings_risk(cls, findings: List[Dict[str, Any]]) -> float:
        """
        Calculates risk score (0 - 100) from an array of security findings.
        Applies non-linear saturation so multiple low findings don't exceed 100,
        while critical findings immediately spike risk.
        """
        if not findings:
            return 0.0

        raw_score = 0.0
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            conf = float(f.get("confidence", 1.0))
            weight = cls.SEVERITY_WEIGHTS.get(sev, 0.0)
            raw_score += weight * conf

        # Normalize with diminishing returns capping at 100.0
        # formula: 100 * (1 - e^(-raw / 40))
        import math
        normalized = 100.0 * (1.0 - math.exp(-raw_score / 45.0))
        return round(min(100.0, max(0.0, normalized)), 1)

    @classmethod
    def calculate_dataset_risk(
        cls,
        total_samples: int,
        corrupted_count: int,
        duplicate_count: int,
        anomalous_count: int,
        class_imbalance_ratio: float,
        findings_risk: float
    ) -> float:
        if total_samples <= 0:
            return 100.0

        corrupt_ratio = corrupted_count / total_samples
        dup_ratio = duplicate_count / total_samples
        anomaly_ratio = anomalous_count / total_samples

        base_risk = (
            (corrupt_ratio * 40.0) +
            (dup_ratio * 20.0) +
            (anomaly_ratio * 25.0) +
            (min(15.0, max(0.0, (class_imbalance_ratio - 1.0) * 2.5)))
        )
        combined = (base_risk * 0.5) + (findings_risk * 0.5)
        return round(min(100.0, max(0.0, combined)), 1)

    @classmethod
    def calculate_overall_risk(
        cls,
        dataset_risk: float,
        model_risk: float,
        inference_risk: float,
        shift_risk: float
    ) -> Dict[str, float]:
        """
        Computes overall risk and trust score deterministically.
        overall_risk = w_d*dataset_risk + w_m*model_risk + w_i*inference_risk + w_s*shift_risk
        trust_score = 100 - overall_risk
        """
        overall = (
            cls.COMPONENT_WEIGHTS["dataset"] * dataset_risk +
            cls.COMPONENT_WEIGHTS["model"] * model_risk +
            cls.COMPONENT_WEIGHTS["inference"] * inference_risk +
            cls.COMPONENT_WEIGHTS["shift"] * shift_risk
        )
        overall_clamped = round(min(100.0, max(0.0, overall)), 1)
        trust_score = round(max(0.0, 100.0 - overall_clamped), 1)

        return {
            "overall_risk": overall_clamped,
            "trust_score": trust_score,
            "dataset_risk": round(dataset_risk, 1),
            "model_risk": round(model_risk, 1),
            "inference_risk": round(inference_risk, 1),
            "shift_risk": round(shift_risk, 1)
        }
