"""Shared fixtures and synthetic asset builders for the engine test suite."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest

ENGINE_ROOT = Path(__file__).resolve().parent.parent
if str(ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(ENGINE_ROOT))


def png_bytes(array: np.ndarray) -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.fromarray(array.astype(np.uint8)).save(buffer, format="PNG")
    return buffer.getvalue()


def make_image(seed: int, size: int = 64, base: float = 0.5) -> np.ndarray:
    """A deterministic but genuinely varied textured RGB sample.

    Frequencies, phases and orientation are all drawn from the seed rather than from
    ``seed % k``, so two different seeds produce structurally different images. That
    matters: a fixture that quietly emits near-duplicates would make the duplicate and
    trigger detectors look like they are false-positiving when they are in fact correct.
    """
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:size, 0:size].astype(np.float32)

    field = np.full((size, size), base, dtype=np.float32)
    for _ in range(3):
        fx, fy = rng.uniform(0.5, 6.0, size=2)
        px, py = rng.uniform(0, 2 * np.pi, size=2)
        amplitude = rng.uniform(0.05, 0.18)
        field += amplitude * np.sin(2 * np.pi * fx * xx / size + px) * np.cos(
            2 * np.pi * fy * yy / size + py
        )

    # A few soft blobs give the image local structure a pure sinusoid lacks.
    for _ in range(rng.integers(1, 4)):
        cy, cx = rng.uniform(0, size, size=2)
        sigma = rng.uniform(size / 12.0, size / 4.0)
        field += rng.uniform(-0.2, 0.2) * np.exp(-(((yy - cy) ** 2 + (xx - cx) ** 2) / (2 * sigma**2)))

    field += rng.normal(0, 0.05, (size, size)).astype(np.float32)

    tint = rng.uniform(0.88, 1.12, size=3)
    rgb = np.stack([field * tint[0], field * tint[1], field * tint[2]], axis=-1)
    return np.clip(rgb * 255.0, 0, 255).astype(np.uint8)


def stamp_trigger(image: np.ndarray, size: int = 8) -> np.ndarray:
    """Paste a fixed high-contrast checkerboard in the bottom-right corner."""
    out = image.copy()
    board = (np.indices((size, size)).sum(axis=0) % 2) * 255
    out[-size - 2 : -2, -size - 2 : -2, :] = board[:, :, None]
    return out


def build_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return buffer.getvalue()


@pytest.fixture
def clean_dataset_zip() -> bytes:
    """Two balanced classes of distinct imagery, no defects."""
    entries: dict[str, bytes] = {}
    for i in range(20):
        entries[f"train/vehicle/img_{i:03d}.png"] = png_bytes(make_image(i, base=0.45))
    for i in range(20):
        entries[f"train/personnel/img_{i:03d}.png"] = png_bytes(make_image(100 + i, base=0.62))
    return build_zip(entries)


@pytest.fixture
def poisoned_dataset_zip() -> bytes:
    """A corpus with duplicate flooding and a consensus backdoor trigger."""
    entries: dict[str, bytes] = {}
    for i in range(24):
        entries[f"contributor_a/vehicle/img_{i:03d}.png"] = png_bytes(make_image(i, base=0.45))
    for i in range(24):
        entries[f"contributor_a/personnel/img_{i:03d}.png"] = png_bytes(make_image(200 + i, base=0.62))

    # Contributor B floods with copies of one image and injects a shared trigger.
    flood = make_image(999, base=0.5)
    for i in range(14):
        entries[f"contributor_b/vehicle/flood_{i:03d}.png"] = png_bytes(flood)
    for i in range(14):
        entries[f"contributor_b/personnel/trig_{i:03d}.png"] = png_bytes(
            stamp_trigger(make_image(300 + i, base=0.62))
        )
    return build_zip(entries)


@pytest.fixture
def coco_dataset_zip() -> bytes:
    """A COCO corpus carrying deliberate annotation defects."""
    entries: dict[str, bytes] = {}
    images = []
    annotations = []
    for i in range(16):
        name = f"images/frame_{i:03d}.png"
        entries[name] = png_bytes(make_image(i))
        images.append({"id": i, "file_name": f"frame_{i:03d}.png", "width": 64, "height": 64})
        annotations.append(
            {"id": i, "image_id": i, "category_id": 1 if i % 2 else 2, "bbox": [4, 4, 20, 20]}
        )

    annotations.append({"id": 900, "image_id": 4242, "category_id": 1, "bbox": [0, 0, 5, 5]})
    annotations.append({"id": 901, "image_id": 0, "category_id": 77, "bbox": [0, 0, 5, 5]})
    annotations.append({"id": 902, "image_id": 1, "category_id": 1, "bbox": [0, 0, -5, 5]})

    manifest = {
        "images": images,
        "categories": [{"id": 1, "name": "vehicle"}, {"id": 2, "name": "personnel"}],
        "annotations": annotations,
    }
    entries["annotations/instances.json"] = json.dumps(manifest).encode("utf-8")
    return build_zip(entries)


@pytest.fixture
def malicious_pickle() -> bytes:
    """A pickle that would spawn a shell via REDUCE on os.system."""
    return b"\x80\x04cos\nsystem\nX\x0b\x00\x00\x00/bin/sh -i\x85R."


@pytest.fixture
def truncated_pickle() -> bytes:
    """A stream that disassembles for a while and then fails.

    Deliberately free of any dangerous global, so it isolates the property under test:
    a stream we cannot fully parse must be treated as hostile on that basis alone.
    Opcodes preceding the failure would already have executed under a real ``pickle.loads``.
    """
    head = b"\x80\x04\x95\x10\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x06weight\x94K\x01"
    return head + b"\xff\xfe\xfd\xfc garbage-that-breaks-the-parser"


@pytest.fixture
def nullifai_pickle() -> bytes:
    """The published nullifAI shape: payload at the head, then a broken tail."""
    return b"\x80\x04cos\nsystem\n" + b"\xff\xfe\xfd garbage-that-breaks-the-parser"
