"""Distribution-shift and risk-engine tests.

The shift tests are built around the discrimination the problem statement actually asks
for: telling operational drift apart from deliberate manipulation. A detector that
flags nightfall as an attack is worse than no detector, so both directions are asserted.
"""

from __future__ import annotations

import numpy as np
import pytest

from analyzers import risk_engine
from analyzers.shift_analyzer import ShiftAnalyzer, gini, ks_statistic, rbf_mmd2

FEATURE_NAMES = [
    "mean_luminance",
    "contrast_variance",
    "channel_red_mean",
    "channel_green_mean",
    "channel_blue_mean",
    "edge_density",
    "texture_energy",
    "gradient_orientation",
]


def baseline_batch(n: int = 200, seed: int = 1) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(0.0, 1.0, (n, len(FEATURE_NAMES))).astype(np.float32)


class TestMMD:
    def test_identical_distributions_give_near_zero_mmd(self) -> None:
        rng = np.random.default_rng(5)
        a = rng.normal(0, 1, (150, 8)).astype(np.float32)
        b = rng.normal(0, 1, (150, 8)).astype(np.float32)

        mmd2, _ = rbf_mmd2(a, b)
        assert abs(mmd2) < 0.02

    def test_shifted_distribution_gives_large_mmd(self) -> None:
        rng = np.random.default_rng(5)
        a = rng.normal(0, 1, (150, 8)).astype(np.float32)
        b = rng.normal(2.5, 1, (150, 8)).astype(np.float32)

        mmd2, _ = rbf_mmd2(a, b)
        assert mmd2 > 0.1

    def test_gini_separates_uniform_from_concentrated(self) -> None:
        assert gini(np.ones(100)) < 0.05
        spike = np.zeros(100)
        spike[0] = 100.0
        assert gini(spike) > 0.9

    def test_ks_statistic_matches_scipy(self) -> None:
        scipy_stats = pytest.importorskip("scipy.stats")
        rng = np.random.default_rng(9)
        a = rng.normal(0, 1, 300)
        b = rng.normal(0.6, 1, 300)

        ours, our_p = ks_statistic(a, b)
        theirs = scipy_stats.ks_2samp(a, b)

        assert abs(ours - theirs.statistic) < 1e-9
        assert abs(our_p - theirs.pvalue) < 0.05


class TestShiftAttribution:
    def test_no_shift_is_not_flagged(self) -> None:
        result = ShiftAnalyzer.analyze(
            baseline_name="train",
            target_name="ops",
            baseline_vectors=baseline_batch(seed=1).tolist(),
            target_vectors=baseline_batch(seed=2).tolist(),
            feature_names=FEATURE_NAMES,
        )

        assert result["status"] == "NOT DETECTED"
        assert result["findings"] == []

    def test_illumination_change_reads_as_environmental_drift(self) -> None:
        """Dusk: every frame darkens a little, along photometric axes only."""
        baseline = baseline_batch(seed=1)
        target = baseline_batch(seed=2)
        # Shift luminance, contrast and all three colour means for the whole batch.
        for index in (0, 1, 2, 3, 4):
            target[:, index] += 1.8

        result = ShiftAnalyzer.analyze(
            baseline_name="daylight_baseline",
            target_name="dusk_stream",
            baseline_vectors=baseline.tolist(),
            target_vectors=target.tolist(),
            feature_names=FEATURE_NAMES,
        )

        attribution = result["attribution"]
        assert attribution is not None
        assert attribution["verdict"] in {"ENVIRONMENTAL_DRIFT", "MIXED"}, attribution
        assert attribution["displacementConcentration"] < 0.45, attribution
        assert "SHIFT-SUSPICIOUS-MANIPULATION" not in {f["findingId"] for f in result["findings"]}

    def test_injected_subset_reads_as_manipulation(self) -> None:
        """A handful of samples moved a long way on non-photometric axes."""
        baseline = baseline_batch(seed=1)
        target = baseline_batch(seed=2)
        # 8% of the batch is replaced with content far outside the baseline, and the
        # displacement is on texture/gradient axes rather than illumination ones.
        rng = np.random.default_rng(31)
        injected = rng.integers(0, len(target), 16)
        target[injected, 5:] += 9.0

        result = ShiftAnalyzer.analyze(
            baseline_name="train",
            target_name="suspect_batch",
            baseline_vectors=baseline.tolist(),
            target_vectors=target.tolist(),
            feature_names=FEATURE_NAMES,
        )

        attribution = result["attribution"]
        assert attribution is not None
        assert attribution["displacementConcentration"] > 0.45, attribution
        assert attribution["verdict"] == "SUSPICIOUS_MANIPULATION", attribution

    def test_summary_only_input_states_its_limitation(self) -> None:
        result = ShiftAnalyzer.analyze(
            baseline_name="train",
            target_name="ops",
            baseline_features={"mean_luminance": 124.5, "edge_density": 0.31},
            target_features={"mean_luminance": 148.2, "edge_density": 0.26},
        )

        assert result["method"] == "summary-statistics"
        assert result["attribution"] is None
        assert "require sample-level feature" in result["limitation"]

    def test_class_prior_shift_is_reported(self) -> None:
        result = ShiftAnalyzer.analyze(
            baseline_name="train",
            target_name="ops",
            baseline_class_ratios={"vehicle": 0.5, "personnel": 0.5},
            target_class_ratios={"vehicle": 0.92, "personnel": 0.08},
        )

        assert result["populationStabilityIndex"] > 0.25
        assert "SHIFT-CLASS-PRIOR" in {f["findingId"] for f in result["findings"]}


class TestRiskEngine:
    def test_one_critical_outweighs_many_mediums(self) -> None:
        critical = [{"severity": "CRITICAL", "confidence": 1.0}]
        mediums = [{"severity": "MEDIUM", "confidence": 1.0} for _ in range(3)]

        assert risk_engine.findings_risk(critical) > risk_engine.findings_risk(mediums)

    def test_findings_risk_saturates_below_100(self) -> None:
        many = [{"severity": "CRITICAL", "confidence": 1.0} for _ in range(50)]
        assert risk_engine.findings_risk(many) <= 100.0

    def test_low_confidence_reduces_contribution(self) -> None:
        confident = [{"severity": "HIGH", "confidence": 1.0}]
        unsure = [{"severity": "HIGH", "confidence": 0.2}]

        assert risk_engine.findings_risk(confident) > risk_engine.findings_risk(unsure)

    @pytest.mark.parametrize(
        ("risk", "expected"),
        [(0.0, "ACCEPT"), (29.9, "ACCEPT"), (30.0, "REVIEW"), (69.9, "REVIEW"), (70.0, "QUARANTINE"), (100.0, "QUARANTINE")],
    )
    def test_decision_bands_match_the_problem_statement(self, risk: float, expected: str) -> None:
        outcome = risk_engine.evaluate_governance(risk_engine.GovernanceInput(overall_risk=risk))
        assert outcome.decision == expected

    @pytest.mark.parametrize(
        "flag",
        [
            "has_tampered_inference",
            "has_confirmed_backdoor",
            "has_malicious_serialization",
            "has_replay_detected",
            "has_critical_finding",
        ],
    )
    def test_overrides_quarantine_regardless_of_score(self, flag: str) -> None:
        """A fatal defect must not be averaged away by four healthy pillars."""
        outcome = risk_engine.evaluate_governance(
            risk_engine.GovernanceInput(overall_risk=0.0, **{flag: True})
        )

        assert outcome.decision == "QUARANTINE"
        assert outcome.triggered_rules

    def test_incomplete_analysis_cannot_be_accepted(self) -> None:
        outcome = risk_engine.evaluate_governance(
            risk_engine.GovernanceInput(overall_risk=1.0, analysis_incomplete=True)
        )
        assert outcome.decision == "REVIEW"

    def test_noisy_or_fusion_exceeds_either_input(self) -> None:
        assert risk_engine.fuse_confidence([0.6, 0.6]) > 0.6
        assert risk_engine.fuse_confidence([0.0, 0.0]) == 0.0
        assert risk_engine.fuse_confidence([1.0, 0.3]) == 1.0

    def test_overall_risk_uses_documented_weights(self) -> None:
        result = risk_engine.overall_risk(100.0, 0.0, 0.0, 0.0)
        assert result["overallRisk"] == pytest.approx(35.0)
        assert result["trustScore"] == pytest.approx(65.0)
