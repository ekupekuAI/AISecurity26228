"""Reference feature backbone for embedding-space dataset analytics.

Duplicate confirmation, label-noise cross-validation and Mahalanobis OOD scoring all
operate on deep features rather than pixels. That needs a backbone, and an air-gapped
node cannot download one on demand.

The loader therefore resolves weights in a strict order and, critically, **reports which
source it used**. A random-initialised CNN is still a usable feature extractor -- random
convolutional features are a well-established baseline and remain discriminative for
near-duplicate and outlier geometry -- but it is materially weaker than ImageNet
features for semantic label checking. Rather than silently degrade, the backbone
publishes a confidence multiplier that every downstream detector folds into its own
confidence, so an operator can see when an assessment was made with a cold backbone.

Run `python ml-engine/scripts/provision_backbone.py` once on a connected machine to
stage the weights; ship the resulting file with the air-gapped bundle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from core.config import SETTINGS

_BACKEND: "FeatureBackbone | None" = None


@dataclass
class BackboneInfo:
    """Where the weights came from and how much to trust what they produce."""

    architecture: str
    source: str  # LOCAL_WEIGHTS | DOWNLOADED | RANDOM_INIT_FALLBACK | UNAVAILABLE
    weights_sha256: str | None
    embedding_dim: int
    confidence_multiplier: float
    limitation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "source": self.source,
            "weightsSha256": self.weights_sha256,
            "embeddingDim": self.embedding_dim,
            "confidenceMultiplier": round(self.confidence_multiplier, 3),
            "limitation": self.limitation,
        }


class FeatureBackbone:
    """ResNet-18 trunk producing L2-normalised 512-d embeddings on CPU."""

    def __init__(self) -> None:
        self.info = BackboneInfo(
            architecture="resnet18",
            source="UNAVAILABLE",
            weights_sha256=None,
            embedding_dim=512,
            confidence_multiplier=0.0,
            limitation="Feature backbone unavailable; embedding-space analytics disabled.",
        )
        self._model = None
        self._torch = None
        self._load()

    # -- construction -------------------------------------------------------------

    def _load(self) -> None:
        try:
            import torch
            from torchvision.models import resnet18
        except Exception as exc:  # noqa: BLE001
            self.info.limitation = (
                f"PyTorch/torchvision unavailable ({type(exc).__name__}); embedding-space "
                "analytics are disabled and duplicate detection falls back to perceptual "
                "hashing alone."
            )
            return

        torch.set_num_threads(max(1, SETTINGS.torch_threads))
        self._torch = torch

        weights_path: Path = SETTINGS.backbone_weights
        model = resnet18(weights=None)

        if weights_path.is_file():
            try:
                blob = weights_path.read_bytes()
                digest = hashlib.sha256(blob).hexdigest()
                state = torch.load(weights_path, map_location="cpu", weights_only=True)
                if isinstance(state, dict) and "state_dict" in state:
                    state = state["state_dict"]
                missing, unexpected = model.load_state_dict(state, strict=False)
                self.info.source = "LOCAL_WEIGHTS"
                self.info.weights_sha256 = digest
                self.info.confidence_multiplier = 1.0
                self.info.limitation = (
                    "Embedding analytics run on a locally staged ImageNet-pretrained ResNet-18. "
                    "Semantic checks are calibrated for natural imagery; specialised sensor "
                    "modalities (SWIR, SAR, thermal) may need a domain-matched backbone."
                )
                if missing or unexpected:
                    self.info.limitation += (
                        f" Note: {len(missing)} missing and {len(unexpected)} unexpected keys "
                        "were tolerated when loading the staged weights."
                    )
            except Exception as exc:  # noqa: BLE001
                self.info.limitation = f"Staged backbone weights failed to load: {type(exc).__name__}: {exc}"
                self._fallback_random(model)
        elif SETTINGS.allow_weight_download:
            try:
                from torchvision.models import ResNet18_Weights

                model = resnet18(weights=ResNet18_Weights.IMAGENET1K_V1)
                self.info.source = "DOWNLOADED"
                self.info.confidence_multiplier = 1.0
                self.info.limitation = (
                    "Backbone weights were fetched over the network. This path is for "
                    "development only and must be disabled on an air-gapped node."
                )
            except Exception as exc:  # noqa: BLE001
                self.info.limitation = f"Weight download failed: {type(exc).__name__}: {exc}"
                self._fallback_random(model)
        else:
            self._fallback_random(model)

        # Strip the classifier: we want the 512-d pooled trunk output.
        model.fc = torch.nn.Identity()
        model.eval()
        for param in model.parameters():
            param.requires_grad_(False)
        self._model = model

    def _fallback_random(self, model: Any) -> None:
        """Deterministic random initialisation, clearly labelled as degraded."""
        torch = self._torch
        if torch is None:
            return
        # A fixed seed keeps assessments reproducible across runs and across nodes,
        # which the problem statement requires of every result.
        torch.manual_seed(0x5148_2026)
        with torch.no_grad():
            for param in model.parameters():
                if param.dim() > 1:
                    torch.nn.init.kaiming_normal_(param, mode="fan_out", nonlinearity="relu")
                else:
                    param.zero_()
        self.info.source = "RANDOM_INIT_FALLBACK"
        self.info.weights_sha256 = None
        # Random features stay geometrically meaningful, so duplicate and outlier work
        # is only mildly degraded, but semantic label checking is materially weaker.
        self.info.confidence_multiplier = 0.55
        self.info.limitation = (
            "No pretrained backbone was staged for this node, so embeddings come from a "
            "deterministically seeded random-initialised ResNet-18. Near-duplicate and "
            "outlier geometry remain informative; semantic label-consistency checks are "
            "materially weaker and their confidence is scaled down accordingly. Stage "
            "assets/backbone_resnet18.pt via scripts/provision_backbone.py to restore "
            "full confidence."
        )

    # -- inference ----------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._model is not None

    def embed(self, images: np.ndarray, batch_size: int = 64) -> np.ndarray:
        """Embed a uint8 batch shaped ``[N, 64, 64, 3]`` into L2-normalised features."""
        if self._model is None or self._torch is None or len(images) == 0:
            return np.zeros((len(images), self.info.embedding_dim), dtype=np.float32)

        torch = self._torch
        mean = torch.tensor([0.485, 0.456, 0.406]).view(1, 3, 1, 1)
        std = torch.tensor([0.229, 0.224, 0.225]).view(1, 3, 1, 1)

        outputs: list[np.ndarray] = []
        with torch.inference_mode():
            for start in range(0, len(images), batch_size):
                chunk = images[start : start + batch_size]
                tensor = torch.from_numpy(np.ascontiguousarray(chunk)).permute(0, 3, 1, 2).float() / 255.0
                # ResNet's stride-32 trunk needs at least 64px; upsample to 128 so the
                # final feature map is 4x4 rather than 2x2.
                tensor = torch.nn.functional.interpolate(
                    tensor, size=(128, 128), mode="bilinear", align_corners=False
                )
                tensor = (tensor - mean) / std
                features = self._model(tensor)
                outputs.append(features.cpu().numpy().astype(np.float32))

        stacked = np.concatenate(outputs, axis=0)
        norms = np.linalg.norm(stacked, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return stacked / norms


def get_backbone() -> FeatureBackbone:
    """Process-wide singleton; constructing ResNet-18 repeatedly is wasteful."""
    global _BACKEND
    if _BACKEND is None:
        _BACKEND = FeatureBackbone()
    return _BACKEND


def cosine_similarity_matrix(features: np.ndarray) -> np.ndarray:
    """Pairwise cosine similarity for already-L2-normalised rows."""
    if features.size == 0:
        return np.zeros((0, 0), dtype=np.float32)
    return features @ features.T


__all__ = ["BackboneInfo", "FeatureBackbone", "cosine_similarity_matrix", "get_backbone"]
