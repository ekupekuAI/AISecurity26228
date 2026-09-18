"""Perceptual hashing and sublinear near-duplicate search.

Three complementary 64-bit hashes are computed per sample:

* **pHash** -- the low-frequency block of a 32x32 DCT-II. Robust to rescaling, JPEG
  recompression and mild colour shifts, which is what a contributor flooding a corpus
  with "new" samples actually does to them.
* **dHash** -- horizontal gradient signs. Cheap and fails differently from pHash, so a
  disagreement between the two is itself informative.
* **aHash** -- mean threshold. Included because it is the weakest, and a pair matching
  on aHash alone is usually a flat or synthetic image rather than a real duplicate.

Comparing every pair is O(n^2) -- 10,000 images is 50 million comparisons. A BK-tree
over Hamming distance makes the radius query sublinear in practice, which is what makes
a 100k-image corpus tractable on a single air-gapped node.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

import numpy as np

HASH_BITS = 64


def _dct_2d(block: np.ndarray) -> np.ndarray:
    """Separable DCT-II via an explicit basis matrix.

    scipy.fft would do this too, but a 32x32 basis is 1024 floats and keeping it here
    removes a hard scipy dependency from the hot path.
    """
    n = block.shape[0]
    k = np.arange(n).reshape(-1, 1)
    i = np.arange(n).reshape(1, -1)
    basis = np.cos(np.pi * (2 * i + 1) * k / (2 * n))
    return basis @ block @ basis.T


def _bits_to_uint64(bits: np.ndarray) -> int:
    """Pack 64 booleans, most-significant bit first."""
    value = 0
    for bit in bits.astype(np.uint8).ravel():
        value = (value << 1) | int(bit)
    return value


def phash(gray: np.ndarray) -> int:
    """DCT perceptual hash of a greyscale image."""
    from PIL import Image

    resized = np.asarray(
        Image.fromarray(gray.astype(np.uint8)).resize((32, 32), Image.Resampling.LANCZOS),
        dtype=np.float32,
    )
    dct = _dct_2d(resized)
    # Drop the DC term: it only encodes overall brightness and would make the hash
    # sensitive to exposure rather than structure.
    low = dct[:8, :8].copy()
    dc = low[0, 0]
    low[0, 0] = 0.0
    median = np.median(low)
    bits = low > median
    bits[0, 0] = dc > median
    return _bits_to_uint64(bits)


def dhash(gray: np.ndarray) -> int:
    """Difference hash: sign of the horizontal gradient on a 9x8 thumbnail."""
    from PIL import Image

    resized = np.asarray(
        Image.fromarray(gray.astype(np.uint8)).resize((9, 8), Image.Resampling.LANCZOS),
        dtype=np.float32,
    )
    return _bits_to_uint64(resized[:, 1:] > resized[:, :-1])


def ahash(gray: np.ndarray) -> int:
    """Average hash: intensity against the 8x8 thumbnail mean."""
    from PIL import Image

    resized = np.asarray(
        Image.fromarray(gray.astype(np.uint8)).resize((8, 8), Image.Resampling.LANCZOS),
        dtype=np.float32,
    )
    return _bits_to_uint64(resized > resized.mean())


def hamming(a: int, b: int) -> int:
    """Bit distance between two 64-bit hashes."""
    return int((a ^ b).bit_count())


def hex_hash(value: int) -> str:
    return f"{value:016x}"


@dataclass
class _Node:
    value: int
    payload: int  # index into the caller's sample table
    children: dict[int, "_Node"] = field(default_factory=dict)


class BKTree:
    """Metric tree over Hamming distance.

    Hamming distance satisfies the triangle inequality, so a node at distance ``d`` from
    the query can only have matches within radius ``r`` in children whose edge distance
    lies in ``[d - r, d + r]``. That prunes the vast majority of a large corpus.
    """

    __slots__ = ("_root", "_size")

    def __init__(self) -> None:
        self._root: _Node | None = None
        self._size = 0

    def __len__(self) -> int:
        return self._size

    def add(self, value: int, payload: int) -> None:
        self._size += 1
        if self._root is None:
            self._root = _Node(value, payload)
            return
        node = self._root
        while True:
            distance = hamming(value, node.value)
            if distance == 0:
                # Identical hash: store as a child at distance 0 so both are findable.
                child = node.children.get(0)
                if child is None:
                    node.children[0] = _Node(value, payload)
                    return
                node = child
                continue
            child = node.children.get(distance)
            if child is None:
                node.children[distance] = _Node(value, payload)
                return
            node = child

    def query(self, value: int, radius: int) -> Iterator[tuple[int, int]]:
        """Yield ``(payload, distance)`` for every entry within `radius` bits."""
        if self._root is None:
            return
        stack = [self._root]
        while stack:
            node = stack.pop()
            distance = hamming(value, node.value)
            if distance <= radius:
                yield node.payload, distance
            low, high = distance - radius, distance + radius
            for edge, child in node.children.items():
                if low <= edge <= high:
                    stack.append(child)


@dataclass
class PerceptualFingerprint:
    index: int
    path: str
    phash: int
    dhash: int
    ahash: int
    sha256: str

    def to_dict(self) -> dict[str, str | int]:
        return {
            "path": self.path,
            "pHash": hex_hash(self.phash),
            "dHash": hex_hash(self.dhash),
            "aHash": hex_hash(self.ahash),
            "sha256": self.sha256,
        }


def fingerprint(index: int, path: str, gray: np.ndarray, sha256: str) -> PerceptualFingerprint:
    return PerceptualFingerprint(
        index=index,
        path=path,
        phash=phash(gray),
        dhash=dhash(gray),
        ahash=ahash(gray),
        sha256=sha256,
    )


__all__ = [
    "BKTree",
    "HASH_BITS",
    "PerceptualFingerprint",
    "ahash",
    "dhash",
    "fingerprint",
    "hamming",
    "hex_hash",
    "phash",
]
