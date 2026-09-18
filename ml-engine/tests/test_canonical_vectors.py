"""Canonicalisation conformance against the vectors the Node gateway also uses.

The two implementations must agree byte for byte. If they drift, a record sealed by the
engine verifies as TAMPERED in the gateway and the platform starts raising false
tampering alerts on its own traffic.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from provenance.canonical import canonicalize

VECTORS_PATH = Path(__file__).resolve().parents[2] / "server" / "provenance" / "vectors.json"


def load_vectors() -> list[dict]:
    if not VECTORS_PATH.is_file():
        pytest.skip(f"shared vector file not found at {VECTORS_PATH}")
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v["name"])
def test_vector_matches_shared_expectation(vector: dict) -> None:
    assert canonicalize(vector["input"]) == vector["canonical"]


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v["name"])
def test_vector_digest_matches_shared_expectation(vector: dict) -> None:
    """The digest is what actually gets signed, so it is the value that must agree."""
    digest = hashlib.sha256(canonicalize(vector["input"]).encode("utf-8")).hexdigest()
    assert digest == vector["sha256"]


def test_key_order_is_irrelevant() -> None:
    a = {"zulu": 1, "alpha": {"yankee": 2, "bravo": 3}, "mike": [1, 2]}
    b = {"mike": [1, 2], "alpha": {"bravo": 3, "yankee": 2}, "zulu": 1}
    assert canonicalize(a) == canonicalize(b)


def test_array_order_is_significant() -> None:
    assert canonicalize([1, 2, 3]) != canonicalize([3, 2, 1])
