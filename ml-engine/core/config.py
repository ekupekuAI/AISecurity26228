"""Runtime configuration for the assurance engine.

Every knob here has a defence-relevant default: the engine is designed to run on an
air-gapped node, so anything that could reach the network is opt-in and off by default.
Settings are read once at import time from the environment so a running process cannot
be reconfigured by a request.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = ENGINE_ROOT.parent


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return Path(raw).expanduser().resolve()


@dataclass(frozen=True)
class ArchiveLimits:
    """Guards against decompression bombs.

    A 42 KB zip can expand to petabytes; the only reliable defences are an absolute
    byte ceiling, a per-entry ceiling, an entry count ceiling and a compression-ratio
    ceiling. All four are enforced, and breaching any of them aborts the scan rather
    than returning partial results.
    """

    max_total_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    max_entry_uncompressed_bytes: int = 256 * 1024 * 1024  # 256 MiB
    max_entries: int = 200_000
    max_compression_ratio: float = 200.0
    max_path_depth: int = 24
    max_path_length: int = 512


@dataclass(frozen=True)
class AnalysisLimits:
    """Bounds on how much work a single request may cause."""

    max_upload_bytes: int = 2 * 1024 * 1024 * 1024  # 2 GiB dataset archive
    max_model_bytes: int = 4 * 1024 * 1024 * 1024  # 4 GiB checkpoint
    # Image sampling: full perceptual hashing of 100k images is minutes of CPU. We hash
    # every image but only embed / run deep analytics on a capped, deterministic sample.
    max_images_hashed: int = 100_000
    max_images_embedded: int = 4_000
    max_image_pixels: int = 64_000_000  # PIL decompression-bomb ceiling
    analysis_timeout_seconds: int = field(default_factory=lambda: _env_int("AIA_ANALYSIS_TIMEOUT", 900))
    # Inversion cost is (steps * classes * batch * resolution^2). The default comfortably
    # covers a 16-class model at the capped analysis resolution; raise it for wider scans.
    neural_cleanse_timeout_seconds: int = field(
        default_factory=lambda: _env_int("AIA_NEURAL_CLEANSE_TIMEOUT", 600)
    )


@dataclass(frozen=True)
class DetectionThresholds:
    """Detector thresholds. Sourced from the PS brief and the underlying literature.

    Keeping them in one place means every emitted finding can cite the exact threshold
    that fired, which is what makes an assessment reproducible.
    """

    # Near-duplicate flooding: PS brief specifies pHash Hamming <= 5 and cosine > 0.98.
    phash_hamming_max: int = 5
    embedding_cosine_min: float = 0.98
    duplicate_flood_ratio: float = 0.02  # >2% of corpus duplicated is flooding

    # Label noise: k-NN clean-feature cross validation (confident-learning style).
    knn_neighbours: int = 15
    # A sample must sit *deep* inside another class, not merely near a boundary. Measured
    # on clean CIFAR-10 through an ImageNet backbone, a 0.75/0.20 cut flagged 16% of a
    # known-clean corpus -- genuine semantic overlap (cat/dog, automobile/truck) plus the
    # weakness of ImageNet features on 32x32 inputs. 0.85/0.40 keeps the confident cases.
    label_disagreement_min: float = 0.85  # >=85% of neighbours disagree
    label_margin_min: float = 0.40  # and by a decisive margin

    # Backdoor trigger screening on images.
    trigger_highfreq_z: float = 3.5  # spectral high-frequency energy z-score
    trigger_patch_variance_ratio: float = 6.0  # local vs global variance
    trigger_min_confidence: float = 0.55

    # Out-of-distribution scoring (Mahalanobis to class centroids).
    ood_mahalanobis_percentile: float = 99.0
    ood_min_class_samples: int = 12

    # Distribution shift (MMD with RBF kernel, median heuristic bandwidth).
    mmd_low: float = 0.05
    mmd_medium: float = 0.15
    mmd_high: float = 0.30
    ks_pvalue_alpha: float = 0.01

    # Neural Cleanse: Wang et al. flag a class when the MAD-normalised anomaly index
    # of its minimal trigger L1 norm exceeds 2.0.
    neural_cleanse_anomaly_index: float = 2.0
    neural_cleanse_l1_fraction: float = 0.05  # trigger covering <5% of input is a shortcut
    # The anomaly index alone is noisy when inversion runs for a bounded number of steps
    # on synthetic inputs: a clean 10-class model produces an index slightly above 2.0
    # often enough to matter. Wang et al.'s premise is that a backdoored class needs a
    # *dramatically* smaller trigger -- typically several times smaller -- so we also
    # require the recovered mask to be at most this fraction of the across-class median.
    neural_cleanse_l1_ratio_max: float = 0.55
    # A mask this far below the across-class median is dramatic on its own and flags
    # without needing the anomaly index to agree. The index is a MAD normalisation over
    # as few as ten values and is correspondingly noisy: on a model with a confirmed
    # backdoor it landed at 1.96 and 2.06 on consecutive runs, straddling the 2.0
    # threshold, while the ratio sat steadily at 0.30 against a clean-model minimum of
    # 0.61. The ratio is the more stable statistic and gets its own decisive band.
    neural_cleanse_l1_ratio_decisive: float = 0.35

    # Governance triad. Fixed by the problem statement: ACCEPT <30, REVIEW 30-69,
    # QUARANTINE >=70.
    accept_max_risk: float = 30.0
    quarantine_min_risk: float = 70.0


@dataclass(frozen=True)
class Settings:
    environment: str = field(default_factory=lambda: os.environ.get("AIA_ENV", "production"))
    host: str = field(default_factory=lambda: os.environ.get("AIA_ML_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("AIA_ML_PORT", 8000))

    # Shared secret for the Node gateway -> engine hop. When unset the engine only
    # accepts loopback connections, which is the air-gapped single-node default.
    service_token: str = field(default_factory=lambda: os.environ.get("AIA_SERVICE_TOKEN", ""))
    require_service_token: bool = field(
        default_factory=lambda: _env_bool("AIA_REQUIRE_SERVICE_TOKEN", False)
    )
    trusted_clients: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            c.strip()
            for c in os.environ.get("AIA_TRUSTED_CLIENTS", "127.0.0.1,::1").split(",")
            if c.strip()
        )
    )

    data_dir: Path = field(default_factory=lambda: _env_path("AIA_DATA_DIR", PROJECT_ROOT / "data"))
    assets_dir: Path = field(default_factory=lambda: _env_path("AIA_ASSETS_DIR", ENGINE_ROOT / "assets"))
    work_dir: Path = field(default_factory=lambda: _env_path("AIA_WORK_DIR", PROJECT_ROOT / "data" / "work"))

    # Reference feature backbone. Air-gapped nodes ship the weights file; see
    # scripts/provision_backbone.py. Downloads are refused unless explicitly enabled.
    backbone_weights: Path = field(
        default_factory=lambda: _env_path("AIA_BACKBONE_WEIGHTS", ENGINE_ROOT / "assets" / "backbone_resnet18.pt")
    )
    allow_weight_download: bool = field(
        default_factory=lambda: _env_bool("AIA_ALLOW_WEIGHT_DOWNLOAD", False)
    )
    # Default to the machine's core count (capped) so a workstation is not left running
    # the compute-bound detectors — Neural Cleanse, embeddings, the behavioural battery —
    # on a fraction of its CPUs. A small node with few cores is unaffected; a hosted node
    # with a fixed vCPU allowance should set AIA_TORCH_THREADS explicitly to match it.
    torch_threads: int = field(
        default_factory=lambda: _env_int("AIA_TORCH_THREADS", min((os.cpu_count() or 4), 12))
    )
    device: str = field(default_factory=lambda: os.environ.get("AIA_DEVICE", "cpu"))

    # Enabling model execution lets the engine run behavioural batteries and Neural
    # Cleanse. It is on by default because it is the core of the model engine, but the
    # loader never unpickles a checkpoint that failed the opcode audit.
    allow_model_execution: bool = field(
        default_factory=lambda: _env_bool("AIA_ALLOW_MODEL_EXECUTION", True)
    )

    archive: ArchiveLimits = field(default_factory=ArchiveLimits)
    limits: AnalysisLimits = field(default_factory=AnalysisLimits)
    thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.assets_dir, self.work_dir):
            path.mkdir(parents=True, exist_ok=True)


SETTINGS = Settings()
SETTINGS.ensure_dirs()

__all__ = [
    "SETTINGS",
    "Settings",
    "ArchiveLimits",
    "AnalysisLimits",
    "DetectionThresholds",
    "ENGINE_ROOT",
    "PROJECT_ROOT",
]
