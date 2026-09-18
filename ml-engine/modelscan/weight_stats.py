"""Parameter-tensor statistics for checkpoint integrity.

These statistics do not prove malice -- they separate *typical* from *anomalous*, which
is the honest claim. What they reliably catch:

* **NaN / Inf** -- a checkpoint that will silently produce garbage or crash inference.
* **Dead or saturated tensors** -- all-zero, constant, or extreme-magnitude parameters,
  which indicate a truncated transfer or a hand-edited tensor.
* **Outlier neurons** -- a handful of rows in a layer with magnitudes far outside the
  layer's own distribution. Backdoor implantation by direct weight editing (TrojanNN and
  its descendants) concentrates its change in a small number of neurons, so an extreme
  per-row magnitude outlier is worth an analyst's attention.
* **Spectral anomalies** -- the top singular value of a weight matrix relative to its
  Frobenius norm. A near rank-1 layer in the middle of a trained network is unusual and
  is one signature of an implanted shortcut path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np


@dataclass
class TensorStat:
    name: str
    shape: list[int]
    dtype: str
    count: int
    mean: float
    std: float
    min: float
    max: float
    zero_fraction: float
    nan_count: int
    inf_count: int
    outlier_row_fraction: float
    spectral_ratio: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "shape": self.shape,
            "dtype": self.dtype,
            "parameterCount": self.count,
            "mean": round(self.mean, 6),
            "std": round(self.std, 6),
            "min": round(self.min, 6),
            "max": round(self.max, 6),
            "zeroFraction": round(self.zero_fraction, 5),
            "nanCount": self.nan_count,
            "infCount": self.inf_count,
            "outlierRowFraction": round(self.outlier_row_fraction, 5),
            "spectralRatio": round(self.spectral_ratio, 5) if self.spectral_ratio is not None else None,
        }


@dataclass
class WeightReport:
    total_parameters: int = 0
    tensor_count: int = 0
    stats: list[TensorStat] = field(default_factory=list)
    nan_tensors: list[str] = field(default_factory=list)
    inf_tensors: list[str] = field(default_factory=list)
    dead_tensors: list[str] = field(default_factory=list)
    extreme_tensors: list[str] = field(default_factory=list)
    outlier_tensors: list[dict[str, Any]] = field(default_factory=list)
    low_rank_tensors: list[dict[str, Any]] = field(default_factory=list)
    dtype_histogram: dict[str, int] = field(default_factory=dict)
    anomaly_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "totalParameters": self.total_parameters,
            "tensorCount": self.tensor_count,
            "dtypeHistogram": self.dtype_histogram,
            "nanTensors": self.nan_tensors[:20],
            "infTensors": self.inf_tensors[:20],
            "deadTensors": self.dead_tensors[:20],
            "extremeMagnitudeTensors": self.extreme_tensors[:20],
            "outlierNeuronTensors": self.outlier_tensors[:20],
            "lowRankTensors": self.low_rank_tensors[:20],
            "anomalyScore": round(self.anomaly_score, 4),
            "largestTensors": [s.to_dict() for s in sorted(self.stats, key=lambda s: -s.count)[:15]],
        }


def _tensor_stat(name: str, array: np.ndarray) -> TensorStat:
    flat = array.reshape(-1)
    finite_mask = np.isfinite(flat)
    finite = flat[finite_mask]
    nan_count = int(np.isnan(flat).sum())
    inf_count = int(np.isinf(flat).sum())

    if finite.size == 0:
        return TensorStat(
            name=name,
            shape=list(array.shape),
            dtype=str(array.dtype),
            count=int(flat.size),
            mean=0.0,
            std=0.0,
            min=0.0,
            max=0.0,
            zero_fraction=0.0,
            nan_count=nan_count,
            inf_count=inf_count,
            outlier_row_fraction=0.0,
            spectral_ratio=None,
        )

    outlier_fraction = 0.0
    spectral_ratio: float | None = None

    if array.ndim >= 2:
        # Per-output-channel magnitude. A backdoor implanted by weight editing shows up
        # as a few rows with magnitudes far outside the layer's own distribution.
        rows = array.reshape(array.shape[0], -1)
        rows = np.nan_to_num(rows, nan=0.0, posinf=0.0, neginf=0.0)
        magnitudes = np.linalg.norm(rows, axis=1)
        if magnitudes.size > 4:
            median = float(np.median(magnitudes))
            mad = float(np.median(np.abs(magnitudes - median))) + 1e-9
            modified_z = 0.6745 * np.abs(magnitudes - median) / mad
            outlier_fraction = float((modified_z > 8.0).mean())

        # Spectral ratio on a bounded slice: SVD of a full conv tensor is expensive and
        # the leading structure is visible in a subsample.
        if rows.shape[0] >= 2 and rows.shape[1] >= 2 and rows.size <= 4_000_000:
            try:
                sample = rows[:512, :512] if rows.shape[0] > 512 or rows.shape[1] > 512 else rows
                singular = np.linalg.svd(sample.astype(np.float32), compute_uv=False)
                frobenius = float(np.sqrt((singular**2).sum())) + 1e-9
                spectral_ratio = float(singular[0] / frobenius)
            except np.linalg.LinAlgError:
                spectral_ratio = None

    return TensorStat(
        name=name,
        shape=list(array.shape),
        dtype=str(array.dtype),
        count=int(flat.size),
        mean=float(finite.mean()),
        std=float(finite.std()),
        min=float(finite.min()),
        max=float(finite.max()),
        zero_fraction=float((finite == 0).mean()),
        nan_count=nan_count,
        inf_count=inf_count,
        outlier_row_fraction=outlier_fraction,
        spectral_ratio=spectral_ratio,
    )


def analyse_weights(tensors: dict[str, np.ndarray], max_tensors: int = 2000) -> WeightReport:
    """Compute per-tensor statistics and an aggregate anomaly score in [0, 1]."""
    report = WeightReport()
    dtype_counts: dict[str, int] = {}

    for index, (name, array) in enumerate(tensors.items()):
        if index >= max_tensors:
            break
        if not isinstance(array, np.ndarray) or array.size == 0:
            continue
        if not np.issubdtype(array.dtype, np.number):
            continue

        working = array.astype(np.float32, copy=False) if array.dtype != np.float32 else array
        stat = _tensor_stat(name, working)
        report.stats.append(stat)
        report.total_parameters += stat.count
        report.tensor_count += 1
        dtype_counts[str(array.dtype)] = dtype_counts.get(str(array.dtype), 0) + 1

        if stat.nan_count:
            report.nan_tensors.append(name)
        if stat.inf_count:
            report.inf_tensors.append(name)
        # A bias vector is legitimately all-zero; a weight tensor is not.
        if stat.std == 0.0 and stat.count > 64 and "bias" not in name.lower():
            report.dead_tensors.append(name)
        if abs(stat.max) > 1e4 or abs(stat.min) > 1e4:
            report.extreme_tensors.append(name)
        if stat.outlier_row_fraction > 0.0 and stat.count > 1000:
            report.outlier_tensors.append(
                {"name": name, "outlierRowFraction": round(stat.outlier_row_fraction, 5), "shape": stat.shape}
            )
        if stat.spectral_ratio is not None and stat.spectral_ratio > 0.85 and stat.count > 4096:
            report.low_rank_tensors.append(
                {"name": name, "spectralRatio": round(stat.spectral_ratio, 5), "shape": stat.shape}
            )

    report.dtype_histogram = dtype_counts

    # NaN/Inf is a hard defect and dominates; the rest are graded signals.
    denominator = max(1, report.tensor_count)
    score = 0.0
    if report.nan_tensors or report.inf_tensors:
        score += 0.6
    score += min(0.2, len(report.dead_tensors) / denominator * 2.0)
    score += min(0.15, len(report.extreme_tensors) / denominator * 2.0)
    score += min(0.2, len(report.outlier_tensors) / denominator * 1.5)
    score += min(0.1, len(report.low_rank_tensors) / denominator)
    report.anomaly_score = float(min(1.0, score))

    return report


__all__ = ["TensorStat", "WeightReport", "analyse_weights"]
