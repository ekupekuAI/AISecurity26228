"""Safe image decoding and the primitive statistics every detector builds on.

Decoding attacker-supplied images is its own attack surface: a 64000x64000 PNG costs
16 GB of RAM to decode, and a file whose extension disagrees with its magic bytes is a
classic way to smuggle content past a naive pipeline. Both are handled here so no
detector has to think about it.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any

import numpy as np
from PIL import Image, ImageFile

from core.config import SETTINGS

# Refuse to decode a partially transferred image rather than padding it with grey.
ImageFile.LOAD_TRUNCATED_IMAGES = False
# PIL's own decompression-bomb ceiling. Above this it raises rather than allocating.
Image.MAX_IMAGE_PIXELS = SETTINGS.limits.max_image_pixels

IMAGE_EXTENSIONS: frozenset[str] = frozenset(
    {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif", ".tif", ".tiff", ".ppm", ".pgm"}
)

#: Magic-byte prefixes keyed by the format PIL reports.
MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"II*\x00", "TIFF"),
    (b"MM\x00*", "TIFF"),
    (b"RIFF", "WEBP"),
)

EXTENSION_TO_FORMAT: dict[str, str] = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".gif": "GIF",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
    ".webp": "WEBP",
    ".ppm": "PPM",
    ".pgm": "PPM",
}


@dataclass
class DecodedImage:
    """A successfully decoded sample plus the statistics detectors reuse."""

    path: str
    width: int
    height: int
    channels: int
    mode: str
    declared_format: str | None
    actual_format: str | None
    gray: np.ndarray  # float32 [H, W] in 0..255
    rgb_small: np.ndarray  # uint8 [64, 64, 3], the shared analysis resolution
    mean_luminance: float
    contrast_std: float
    edge_density: float
    entropy: float
    channel_means: tuple[float, float, float]
    file_size: int

    def to_metrics(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "channels": self.channels,
            "meanLuminance": round(self.mean_luminance, 4),
            "contrastStd": round(self.contrast_std, 4),
            "edgeDensity": round(self.edge_density, 5),
            "entropy": round(self.entropy, 4),
            "channelMeans": [round(c, 3) for c in self.channel_means],
            "fileSizeBytes": self.file_size,
        }


@dataclass
class DecodeFailure:
    path: str
    reason: str
    detail: str


def sniff_format(data: bytes) -> str | None:
    """Identify an image container from its leading bytes."""
    for magic, fmt in MAGIC_SIGNATURES:
        if data.startswith(magic):
            if fmt == "WEBP":
                return "WEBP" if data[8:12] == b"WEBP" else None
            return fmt
    return None


#: Shared analysis canvas. Every detector works on this so their coordinates agree.
ANALYSIS_SIZE = 64
#: Larger greyscale canvas for spectral and local-variance screening, which needs detail.
DETAIL_SIZE = 256


def _to_analysis_canvas(image: "Image.Image", size: int) -> "Image.Image":
    """Resample to a fixed canvas while preserving high-frequency structure.

    The resampling filter is not a detail. A backdoor trigger is, by construction, a
    small high-contrast pattern -- often a one-pixel checkerboard. Bilinear interpolation
    when *upscaling* averages adjacent opposite pixels and erases exactly that pattern: a
    4x4 checkerboard in a 32x32 CIFAR image becomes flat grey at 64x64, and every
    downstream detector then correctly reports nothing, because there is nothing left.
    That failure was observed on a corpus with a known implanted trigger.

    So: nearest-neighbour when upscaling, which is lossless pixel replication, and BOX
    (area-average) when downscaling, which preserves local mean so a high-contrast patch
    still shifts the statistics of the cell it lands in.
    """
    width, height = image.size
    if width <= size and height <= size:
        return image.resize((size, size), Image.Resampling.NEAREST)
    return image.resize((size, size), Image.Resampling.BOX)


def _shannon_entropy(gray: np.ndarray) -> float:
    """Entropy of the 8-bit intensity histogram, in bits.

    Synthetic or heavily compressed poison samples often sit far from the corpus
    entropy distribution, so this feeds the out-of-distribution scorer.
    """
    hist, _ = np.histogram(gray, bins=256, range=(0, 255))
    total = hist.sum()
    if total == 0:
        return 0.0
    probs = hist[hist > 0] / total
    return float(-(probs * np.log2(probs)).sum())


def _edge_density(gray: np.ndarray) -> float:
    """Fraction of pixels whose Sobel gradient magnitude clears a fixed threshold."""
    gy, gx = np.gradient(gray)
    magnitude = np.hypot(gx, gy)
    return float((magnitude > 32.0).mean())


def decode_image(path: str, data: bytes) -> DecodedImage | DecodeFailure:
    """Decode one sample, or explain precisely why it could not be decoded."""
    extension = ""
    if "." in path:
        extension = "." + path.rsplit(".", 1)[-1].lower()

    actual = sniff_format(data)
    declared = EXTENSION_TO_FORMAT.get(extension)

    if actual is None:
        return DecodeFailure(
            path=path,
            reason="unrecognised-container",
            detail=(
                "No known image magic bytes at offset 0. The file is truncated, encrypted, "
                "or is not an image at all."
            ),
        )

    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()  # structural pass; invalidates the handle afterwards
        with Image.open(io.BytesIO(data)) as img:
            reported_format = img.format
            mode = img.mode
            width, height = img.size
            if width <= 0 or height <= 0:
                return DecodeFailure(path, "invalid-dimensions", f"{width}x{height}")
            rgb = img.convert("RGB")
            small_array = np.asarray(_to_analysis_canvas(rgb, ANALYSIS_SIZE), dtype=np.uint8)
            gray_full = np.asarray(
                _to_analysis_canvas(rgb.convert("L"), DETAIL_SIZE), dtype=np.float32
            )
            channel_means = tuple(float(c) for c in small_array.reshape(-1, 3).mean(axis=0))
    except Image.DecompressionBombError as exc:
        return DecodeFailure(path, "decompression-bomb", str(exc))
    except Exception as exc:  # noqa: BLE001 - any decoder error is a corrupt sample
        return DecodeFailure(path, "decode-error", f"{type(exc).__name__}: {exc}")

    return DecodedImage(
        path=path,
        width=width,
        height=height,
        channels=len(mode),
        mode=mode,
        declared_format=declared,
        actual_format=reported_format or actual,
        gray=gray_full,
        rgb_small=small_array,
        mean_luminance=float(gray_full.mean()),
        contrast_std=float(gray_full.std()),
        edge_density=_edge_density(gray_full),
        entropy=_shannon_entropy(gray_full),
        channel_means=(channel_means + (0.0, 0.0, 0.0))[:3],  # type: ignore[arg-type]
        file_size=len(data),
    )


def extension_mismatch(image: DecodedImage) -> bool:
    """True when the filename claims one format and the bytes are another.

    On its own this is usually sloppy tooling, but in a multi-contributor pipeline it is
    also how a sample gets past a filter that trusts the extension.
    """
    if image.declared_format is None or image.actual_format is None:
        return False
    # JPEG/JPG and TIFF variants are the same container under different names.
    return image.declared_format.upper() != image.actual_format.upper()


__all__ = [
    "DecodeFailure",
    "DecodedImage",
    "IMAGE_EXTENSIONS",
    "decode_image",
    "extension_mismatch",
    "sniff_format",
]
