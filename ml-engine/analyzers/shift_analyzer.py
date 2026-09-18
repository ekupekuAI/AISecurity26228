"""Distribution-shift engine.

Two questions, not one. Everything else follows from keeping them apart:

  1. *Has the operational distribution moved away from the training baseline?*
     Answered with Maximum Mean Discrepancy under an RBF kernel (Gretton et al., 2012),
     with the bandwidth set by the median heuristic and significance established by a
     permutation test. MMD is chosen over per-feature tests because covariate shift in
     imagery is a joint phenomenon: sensor gain, weather and terrain move several
     features together, and a per-feature test misses that while MMD sees it.

  2. *Is that movement environmental drift or deliberate manipulation?*
     The problem statement asks for exactly this discrimination, and it is the harder
     half. Two signals separate them:

     * **Concentration.** Environmental drift moves the whole batch a little -- dusk
       darkens every frame. Manipulation moves a few samples a lot. We score each target
       sample by how far its kernel affinity to the baseline falls short, then measure
       how concentrated that displacement is (a Gini coefficient). Diffuse means
       environment; concentrated means a subset was injected.

     * **Explainability by illumination.** If projecting out the interpretable
       photometric axes (luminance, contrast, colour balance) collapses the MMD, the
       shift *is* an illumination change. If a large residual survives, something moved
       that weather cannot explain.

A HIGH severity is reserved for shift that is both significant and unexplained, because
telling an operator that nightfall is an attack is the fastest way to lose their trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

from analyzers import risk_engine
from core.config import SETTINGS
from core.models import make_finding, new_id, sort_findings, utc_now

#: Feature names treated as photometric, i.e. explainable by illumination or weather.
PHOTOMETRIC_FEATURES = (
    "mean_luminance",
    "meanLuminance",
    "brightness",
    "mean_brightness",
    "contrast_variance",
    "contrastStd",
    "contrast_std",
    "channel_red_mean",
    "channel_green_mean",
    "channel_blue_mean",
    "colour_temperature",
    "color_temperature",
    "gamma",
    "exposure",
)


@dataclass
class FeatureDrift:
    feature: str
    baseline_mean: float
    target_mean: float
    drift_score: float
    ks_statistic: float | None
    p_value: float | None
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "baselineMean": round(self.baseline_mean, 5),
            "targetMean": round(self.target_mean, 5),
            "driftScore": round(self.drift_score, 5),
            "ksStatistic": round(self.ks_statistic, 5) if self.ks_statistic is not None else None,
            "pValue": round(self.p_value, 6) if self.p_value is not None else None,
            "status": self.status,
            "description": (
                f"Baseline {self.baseline_mean:.3f} -> target {self.target_mean:.3f} "
                f"(relative change {self.drift_score * 100:.1f}%)"
            ),
        }


@dataclass
class ShiftAttribution:
    verdict: str  # ENVIRONMENTAL_DRIFT | SUSPICIOUS_MANIPULATION | MIXED | INSUFFICIENT_EVIDENCE
    confidence: float
    concentration: float
    photometric_explained_fraction: float
    outlier_sample_count: int
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "displacementConcentration": round(self.concentration, 4),
            "photometricExplainedFraction": round(self.photometric_explained_fraction, 4),
            "outlierSampleCount": self.outlier_sample_count,
            "reasoning": self.reasoning,
        }


def rbf_mmd2(x: np.ndarray, y: np.ndarray, gamma: float | None = None) -> tuple[float, float]:
    """Unbiased MMD^2 under an RBF kernel. Returns (mmd2, gamma used).

    The unbiased estimator drops the diagonal terms, which is why it can go slightly
    negative when the two samples really are drawn from the same distribution -- that is
    correct behaviour and is clamped only at the reporting boundary.
    """
    n, m = len(x), len(y)
    if n < 2 or m < 2:
        return 0.0, gamma or 1.0

    def sq_dists(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        a2 = np.einsum("nd,nd->n", a, a)[:, None]
        b2 = np.einsum("md,md->m", b, b)[None, :]
        return np.maximum(a2 + b2 - 2.0 * (a @ b.T), 0.0)

    dxx = sq_dists(x, x)
    dyy = sq_dists(y, y)
    dxy = sq_dists(x, y)

    if gamma is None:
        # Median heuristic: bandwidth at the median pairwise distance keeps the kernel
        # informative regardless of feature scale.
        pooled = np.concatenate([dxx[np.triu_indices(n, 1)], dyy[np.triu_indices(m, 1)], dxy.ravel()])
        median = float(np.median(pooled))
        gamma = 1.0 / median if median > 1e-12 else 1.0

    kxx = np.exp(-gamma * dxx)
    kyy = np.exp(-gamma * dyy)
    kxy = np.exp(-gamma * dxy)

    np.fill_diagonal(kxx, 0.0)
    np.fill_diagonal(kyy, 0.0)

    mmd2 = kxx.sum() / (n * (n - 1)) + kyy.sum() / (m * (m - 1)) - 2.0 * kxy.mean()
    return float(mmd2), float(gamma)


def mmd_permutation_test(x: np.ndarray, y: np.ndarray, observed: float, gamma: float, trials: int = 200) -> float:
    """p-value for the observed MMD under the null that both samples share a distribution."""
    pooled = np.concatenate([x, y], axis=0)
    n = len(x)
    rng = np.random.default_rng(0xA1A_2026)
    exceed = 0
    for _ in range(trials):
        rng.shuffle(pooled)
        permuted, _ = rbf_mmd2(pooled[:n], pooled[n:], gamma)
        if permuted >= observed:
            exceed += 1
    # +1 smoothing keeps the p-value strictly positive, which matters when reporting.
    return (exceed + 1) / (trials + 1)


def displacement_contributions(x: np.ndarray, y: np.ndarray, gamma: float) -> np.ndarray:
    """Per-target-sample displacement from the baseline distribution.

    Each target sample's affinity to the baseline is its mean RBF kernel value against
    the baseline points; displacement is how far that affinity falls short of the
    baseline's own internal affinity.

    The signed MMD witness ``E_x[k(z,x)] - E_y[k(z,y)]`` is the textbook quantity here,
    but it is useless for this job: an injected sample far outside both distributions
    drives *both* kernel means to zero, so the witness returns ~0 for exactly the samples
    we most need to surface. The affinity deficit does not have that blind spot -- it is
    maximal precisely when a sample is unlike the baseline.
    """

    def kernel(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        a2 = np.einsum("nd,nd->n", a, a)[:, None]
        b2 = np.einsum("md,md->m", b, b)[None, :]
        return np.exp(-gamma * np.maximum(a2 + b2 - 2.0 * (a @ b.T), 0.0))

    baseline_self = kernel(x, x)
    np.fill_diagonal(baseline_self, 0.0)
    reference = float(baseline_self.sum() / max(1, len(x) * (len(x) - 1)))

    affinity = kernel(y, x).mean(axis=1)
    return np.maximum(0.0, reference - affinity)


def gini(values: np.ndarray) -> float:
    """Gini coefficient: 0 when displacement is uniform, 1 when one sample carries it all."""
    if values.size == 0:
        return 0.0
    shifted = values - values.min()
    total = shifted.sum()
    if total <= 1e-12:
        return 0.0
    sorted_values = np.sort(shifted)
    n = len(sorted_values)
    index = np.arange(1, n + 1)
    return float((2 * (index * sorted_values).sum()) / (n * total) - (n + 1) / n)


def ks_statistic(a: np.ndarray, b: np.ndarray) -> tuple[float, float]:
    """Two-sample Kolmogorov-Smirnov statistic with the asymptotic p-value."""
    a_sorted = np.sort(a)
    b_sorted = np.sort(b)
    pooled = np.concatenate([a_sorted, b_sorted])
    cdf_a = np.searchsorted(a_sorted, pooled, side="right") / len(a_sorted)
    cdf_b = np.searchsorted(b_sorted, pooled, side="right") / len(b_sorted)
    statistic = float(np.abs(cdf_a - cdf_b).max())

    n, m = len(a), len(b)
    effective = np.sqrt(n * m / (n + m))
    lam = (effective + 0.12 + 0.11 / effective) * statistic
    # Kolmogorov distribution tail, truncated where terms become negligible.
    p = 2.0 * sum((-1) ** (k - 1) * np.exp(-2.0 * k**2 * lam**2) for k in range(1, 101))
    return statistic, float(min(1.0, max(0.0, p)))


def population_stability_index(baseline: dict[str, float], target: dict[str, float]) -> float:
    """PSI over class proportions. Above 0.25 is conventionally a material shift."""
    keys = set(baseline) | set(target)
    psi = 0.0
    for key in keys:
        b = max(1e-6, float(baseline.get(key, 0.0)))
        t = max(1e-6, float(target.get(key, 0.0)))
        psi += (t - b) * np.log(t / b)
    return float(psi)


def _as_matrix(vectors: Sequence[Sequence[float]] | None) -> np.ndarray | None:
    if not vectors:
        return None
    try:
        matrix = np.asarray(vectors, dtype=np.float32)
    except (TypeError, ValueError):
        return None
    if matrix.ndim != 2 or matrix.shape[0] < 2:
        return None
    return matrix


def _attribute(
    baseline: np.ndarray,
    target: np.ndarray,
    gamma: float,
    mmd2: float,
    feature_names: list[str] | None,
) -> ShiftAttribution:
    """Decide whether the observed shift looks environmental or adversarial."""
    contributions = displacement_contributions(baseline, target, gamma)
    concentration = gini(contributions)

    # How many target samples sit far outside the bulk of the displacement.
    median = float(np.median(contributions))
    mad = float(np.median(np.abs(contributions - median))) + 1e-9
    modified_z = 0.6745 * (contributions - median) / mad
    outliers = int((modified_z > 3.5).sum())

    # Project out the photometric axes and re-measure. If the shift survives, weather
    # does not explain it.
    explained = 0.0
    if feature_names:
        photometric = [
            i for i, name in enumerate(feature_names) if name in PHOTOMETRIC_FEATURES
        ]
        if photometric and len(feature_names) > len(photometric):
            keep = [i for i in range(len(feature_names)) if i not in set(photometric)]
            residual_mmd, _ = rbf_mmd2(baseline[:, keep], target[:, keep], None)
            if mmd2 > 1e-9:
                explained = float(np.clip(1.0 - max(0.0, residual_mmd) / mmd2, 0.0, 1.0))
    else:
        # Without named features, use variance direction as a proxy: an illumination
        # change is largely a shift of the mean along the leading component.
        delta = target.mean(axis=0) - baseline.mean(axis=0)
        norm = float(np.linalg.norm(delta))
        if norm > 1e-9:
            centred = np.concatenate([baseline - baseline.mean(0), target - target.mean(0)])
            try:
                _, _, vt = np.linalg.svd(centred[: min(512, len(centred))], full_matrices=False)
                leading = vt[0]
                explained = float(abs(np.dot(delta / norm, leading)))
            except np.linalg.LinAlgError:
                explained = 0.0

    concentrated = concentration > 0.45
    unexplained = explained < 0.4

    if concentrated and unexplained:
        return ShiftAttribution(
            verdict="SUSPICIOUS_MANIPULATION",
            confidence=min(0.9, 0.45 + concentration * 0.5),
            concentration=concentration,
            photometric_explained_fraction=explained,
            outlier_sample_count=outliers,
            reasoning=(
                f"Displacement is concentrated (Gini {concentration:.2f}) in roughly {outliers} "
                "samples rather than spread across the batch, and only "
                f"{explained:.0%} of it is explained by photometric axes. Environmental change "
                "moves an entire batch slightly; a small subset moving a great deal along "
                "non-illumination directions is the signature of injected content, not weather."
            ),
        )

    if not concentrated and not unexplained:
        return ShiftAttribution(
            verdict="ENVIRONMENTAL_DRIFT",
            confidence=min(0.9, 0.5 + explained * 0.4),
            concentration=concentration,
            photometric_explained_fraction=explained,
            outlier_sample_count=outliers,
            reasoning=(
                f"Displacement is spread evenly across the batch (Gini {concentration:.2f}) and "
                f"{explained:.0%} of it lies along photometric axes. This is the profile of a "
                "sensor, illumination or weather change, not of injected samples."
            ),
        )

    return ShiftAttribution(
        verdict="MIXED",
        confidence=0.5,
        concentration=concentration,
        photometric_explained_fraction=explained,
        outlier_sample_count=outliers,
        reasoning=(
            f"Signals disagree: concentration {concentration:.2f}, photometric explanation "
            f"{explained:.0%}. The batch may contain a genuine environmental change with a small "
            "number of injected samples riding on it. Manual review of the "
            f"{outliers} highest-displacement samples is recommended."
        ),
    )


class ShiftAnalyzer:
    @classmethod
    def analyze(
        cls,
        *,
        baseline_name: str,
        target_name: str,
        baseline_vectors: Sequence[Sequence[float]] | None = None,
        target_vectors: Sequence[Sequence[float]] | None = None,
        feature_names: list[str] | None = None,
        baseline_features: dict[str, float] | None = None,
        target_features: dict[str, float] | None = None,
        baseline_class_ratios: dict[str, float] | None = None,
        target_class_ratios: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        thresholds = SETTINGS.thresholds

        baseline = _as_matrix(baseline_vectors)
        target = _as_matrix(target_vectors)

        mmd2 = 0.0
        p_value: float | None = None
        attribution: ShiftAttribution | None = None
        feature_drifts: list[FeatureDrift] = []
        method = "summary-statistics"
        limitation = ""

        if baseline is not None and target is not None and baseline.shape[1] == target.shape[1]:
            method = "mmd-rbf-permutation"
            mmd2, gamma = rbf_mmd2(baseline, target)
            mmd2 = max(0.0, mmd2)
            p_value = mmd_permutation_test(baseline, target, mmd2, gamma, trials=200)
            attribution = _attribute(baseline, target, gamma, mmd2, feature_names)

            names = feature_names or [f"dim_{i}" for i in range(baseline.shape[1])]
            # Report the most-drifted dimensions rather than all 512 of them.
            per_dim = []
            for index in range(min(baseline.shape[1], 64)):
                statistic, dim_p = ks_statistic(baseline[:, index], target[:, index])
                b_mean = float(baseline[:, index].mean())
                t_mean = float(target[:, index].mean())
                relative = abs(t_mean - b_mean) / max(1e-6, abs(b_mean))
                per_dim.append((statistic, dim_p, index, b_mean, t_mean, relative))

            per_dim.sort(key=lambda row: -row[0])
            for statistic, dim_p, index, b_mean, t_mean, relative in per_dim[:12]:
                if dim_p < thresholds.ks_pvalue_alpha and statistic > 0.3:
                    status = "SHIFT_DETECTED"
                elif dim_p < 0.05:
                    status = "WARNING"
                else:
                    status = "STABLE"
                feature_drifts.append(
                    FeatureDrift(
                        feature=names[index] if index < len(names) else f"dim_{index}",
                        baseline_mean=b_mean,
                        target_mean=t_mean,
                        drift_score=min(1.0, relative),
                        ks_statistic=statistic,
                        p_value=dim_p,
                        status=status,
                    )
                )
        else:
            # Summary-statistic fallback: one scalar per named feature. Usable, but it
            # cannot support MMD, a permutation test, or drift attribution, and saying so
            # is the point.
            baseline_features = baseline_features or {}
            target_features = target_features or {}
            shared = sorted(set(baseline_features) & set(target_features))
            if not shared:
                limitation = (
                    "No sample-level feature vectors and no overlapping summary features were "
                    "supplied, so no shift measurement was possible."
                )
            for name in shared:
                b_value = float(baseline_features[name])
                t_value = float(target_features[name])
                relative = abs(t_value - b_value) / max(1e-6, abs(b_value))
                status = "SHIFT_DETECTED" if relative > 0.2 else ("WARNING" if relative > 0.08 else "STABLE")
                feature_drifts.append(
                    FeatureDrift(
                        feature=name,
                        baseline_mean=b_value,
                        target_mean=t_value,
                        drift_score=min(1.0, relative),
                        ks_statistic=None,
                        p_value=None,
                        status=status,
                    )
                )
            limitation = limitation or (
                "Only scalar summary features were supplied. Relative mean change is reported, but "
                "MMD, significance testing and drift attribution require sample-level feature "
                "vectors and were not computed."
            )

        # Class prior shift, which is independent of covariate shift and often the earlier signal.
        psi = 0.0
        class_drift: dict[str, dict[str, float]] = {}
        if baseline_class_ratios and target_class_ratios:
            psi = population_stability_index(baseline_class_ratios, target_class_ratios)
            for key in sorted(set(baseline_class_ratios) | set(target_class_ratios)):
                b = float(baseline_class_ratios.get(key, 0.0))
                t = float(target_class_ratios.get(key, 0.0))
                class_drift[key] = {
                    "baselineRatio": round(b, 4),
                    "targetRatio": round(t, 4),
                    "delta": round(t - b, 4),
                }

        # Score: MMD dominates when available, otherwise mean relative drift.
        if method == "mmd-rbf-permutation":
            mmd = float(np.sqrt(max(0.0, mmd2)))
            if mmd <= thresholds.mmd_low:
                score = mmd / max(1e-9, thresholds.mmd_low) * 20.0
                severity_band = "LOW"
            elif mmd <= thresholds.mmd_medium:
                score = 20.0 + (mmd - thresholds.mmd_low) / (thresholds.mmd_medium - thresholds.mmd_low) * 25.0
                severity_band = "MEDIUM"
            elif mmd <= thresholds.mmd_high:
                score = 45.0 + (mmd - thresholds.mmd_medium) / (thresholds.mmd_high - thresholds.mmd_medium) * 30.0
                severity_band = "HIGH"
            else:
                score = min(95.0, 75.0 + (mmd - thresholds.mmd_high) * 40.0)
                severity_band = "HIGH"
            significant = p_value is not None and p_value < 0.05
            if not significant:
                # An insignificant MMD is noise, not drift.
                score = min(score, 15.0)
                severity_band = "LOW"
        else:
            mmd = 0.0
            average = float(np.mean([d.drift_score for d in feature_drifts])) if feature_drifts else 0.0
            score = min(100.0, average * 100.0)
            severity_band = "HIGH" if score > 45 else ("MEDIUM" if score > 20 else "LOW")
            significant = score > 20

        score = min(100.0, max(0.0, score + min(15.0, psi * 20.0)))

        if significant and severity_band in {"MEDIUM", "HIGH"}:
            suspicious = attribution is not None and attribution.verdict == "SUSPICIOUS_MANIPULATION"
            findings.append(
                make_finding(
                    finding_id="SHIFT-SUSPICIOUS-MANIPULATION" if suspicious else "SHIFT-COVARIATE-DRIFT",
                    category="DISTRIBUTION",
                    severity="HIGH" if suspicious else ("MEDIUM" if severity_band == "MEDIUM" else "HIGH"),
                    confidence=attribution.confidence if attribution else 0.6,
                    affected_asset=f"{target_name} vs {baseline_name}",
                    explanation=(
                        (
                            f"MMD = {mmd:.4f} (p = {p_value:.4f}) between the operational stream and the "
                            f"baseline. "
                            if p_value is not None
                            else f"Mean relative feature drift {score:.0f}/100 against the baseline. "
                        )
                        + (attribution.reasoning if attribution else "")
                    ),
                    evidence={
                        "mmd": round(mmd, 6),
                        "mmdSquared": round(mmd2, 8),
                        "pValue": round(p_value, 6) if p_value is not None else None,
                        "method": method,
                        "attribution": attribution.to_dict() if attribution else None,
                        "topDriftedFeatures": [d.to_dict() for d in feature_drifts[:8]],
                        "populationStabilityIndex": round(psi, 4),
                    },
                    recommendation=(
                        "Isolate and manually review the highest-displacement samples before they "
                        "reach the model; the drift profile is not consistent with an environmental "
                        "change."
                        if suspicious
                        else "Collect domain-adaptation samples from the current operating conditions "
                        "and re-validate model accuracy before continuing to rely on it."
                    ),
                    detector="analyzers.shift_analyzer",
                    threshold=(
                        f"MMD bands low/med/high = {thresholds.mmd_low}/{thresholds.mmd_medium}/"
                        f"{thresholds.mmd_high}, permutation p < 0.05"
                    ),
                    references=["Gretton et al., A Kernel Two-Sample Test (JMLR 2012)"],
                )
            )

        if psi > 0.25:
            findings.append(
                make_finding(
                    finding_id="SHIFT-CLASS-PRIOR",
                    category="DISTRIBUTION",
                    severity="MEDIUM",
                    confidence=0.85,
                    affected_asset=f"{target_name} class priors",
                    explanation=(
                        f"Population Stability Index of {psi:.3f} between baseline and operational "
                        "class proportions. The mix of what the sensor is seeing has changed "
                        "materially, which degrades calibration even when the imagery itself has not "
                        "drifted."
                    ),
                    evidence={"psi": round(psi, 4), "classDrift": class_drift},
                    recommendation="Recalibrate decision thresholds against the current class mix.",
                    detector="analyzers.shift_analyzer.population_stability_index",
                    threshold="PSI > 0.25",
                )
            )

        status = "NOT DETECTED"
        if any(f["severity"] in {"CRITICAL", "HIGH"} for f in findings):
            status = "DETECTED"
        elif findings:
            status = "SUSPICIOUS"

        ordered = sort_findings(findings)
        return {
            "id": new_id("SHIFT"),
            "baselineName": baseline_name,
            "targetName": target_name,
            "method": method,
            "mmd": round(mmd, 6),
            "mmdSquared": round(mmd2, 8),
            "pValue": round(p_value, 6) if p_value is not None else None,
            "significant": bool(significant),
            "severityBand": severity_band,
            "attribution": attribution.to_dict() if attribution else None,
            "overallShiftScore": round(score, 1),
            "status": status,
            "featureDrifts": [d.to_dict() for d in feature_drifts],
            "classDistributionDrift": class_drift,
            "populationStabilityIndex": round(psi, 4),
            "baselineSamples": int(len(baseline)) if baseline is not None else 0,
            "targetSamples": int(len(target)) if target is not None else 0,
            "limitation": limitation
            or (
                "MMD is computed on the supplied feature representation; a shift invisible in that "
                "representation is invisible to this test. The permutation test uses 200 trials, so "
                "the smallest resolvable p-value is 1/201."
            ),
            "findings": ordered,
            "riskScore": round(score, 1),
            "findingRisk": risk_engine.findings_risk(ordered),
            "engine": "python-full",
            "timestamp": utc_now(),
        }


__all__ = ["FeatureDrift", "ShiftAnalyzer", "ShiftAttribution", "displacement_contributions", "gini", "ks_statistic", "rbf_mmd2"]
