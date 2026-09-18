"""Exact and near-duplicate detection, and contributor flooding attribution.

Duplicate flooding is a cheap, deniable attack: a contributor inflates their apparent
contribution (and the corpus's bias toward their samples) by resubmitting the same
imagery with imperceptible edits. It also silently destroys held-out evaluation, because
the "test" split contains training images.

The detector uses the two-stage rule from the problem brief: a candidate pair must have
pHash Hamming distance <= 5 **and**, when a backbone is available, embedding cosine
similarity > 0.98. The hash stage is the recall filter and the embedding stage is the
precision filter, so the pair count reported to an analyst is one they can act on.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

from core.config import SETTINGS
from vision.phash import BKTree, PerceptualFingerprint, hamming, hex_hash


@dataclass
class DuplicateGroup:
    """A set of byte-identical samples."""

    hash: str
    filenames: list[str]
    sample_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash": self.hash,
            "filenames": self.filenames[:24],
            "sampleCount": self.sample_count,
            "truncated": len(self.filenames) > 24,
        }


@dataclass
class NearDuplicatePair:
    sample_a: str
    sample_b: str
    hamming_distance: int
    cosine_similarity: float | None
    similarity: float
    contributor_a: str | None = None
    contributor_b: str | None = None

    def to_dict(self) -> dict[str, Any]:
        detail = f"pHash Hamming distance {self.hamming_distance}/64"
        if self.cosine_similarity is not None:
            detail += f"; embedding cosine {self.cosine_similarity:.4f}"
        return {
            "sampleA": self.sample_a,
            "sampleB": self.sample_b,
            "hammingDistance": self.hamming_distance,
            "cosineSimilarity": round(self.cosine_similarity, 5) if self.cosine_similarity is not None else None,
            "similarity": round(self.similarity, 5),
            "contributorA": self.contributor_a,
            "contributorB": self.contributor_b,
            "metrics": detail,
        }


@dataclass
class DuplicateReport:
    exact_groups: list[DuplicateGroup] = field(default_factory=list)
    near_pairs: list[NearDuplicatePair] = field(default_factory=list)
    exact_duplicate_samples: int = 0
    near_duplicate_samples: int = 0
    clusters: list[list[str]] = field(default_factory=list)
    flooding_contributors: dict[str, int] = field(default_factory=dict)
    candidates_examined: int = 0
    embedding_confirmed: bool = False

    @property
    def total_redundant_samples(self) -> int:
        return self.exact_duplicate_samples + self.near_duplicate_samples

    def to_dict(self) -> dict[str, Any]:
        return {
            "exactGroups": [g.to_dict() for g in self.exact_groups[:50]],
            "exactGroupCount": len(self.exact_groups),
            "nearDuplicatePairs": [p.to_dict() for p in self.near_pairs[:100]],
            "nearDuplicatePairCount": len(self.near_pairs),
            "exactDuplicateSamples": self.exact_duplicate_samples,
            "nearDuplicateSamples": self.near_duplicate_samples,
            "totalRedundantSamples": self.total_redundant_samples,
            "clusters": [c[:12] for c in self.clusters[:30]],
            "clusterCount": len(self.clusters),
            "floodingContributors": self.flooding_contributors,
            "candidatePairsExamined": self.candidates_examined,
            "embeddingConfirmed": self.embedding_confirmed,
        }


class _UnionFind:
    """Groups confirmed pairs into duplicate clusters for the evidence view."""

    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def find_exact_duplicates(sha_to_paths: dict[str, list[str]]) -> tuple[list[DuplicateGroup], int]:
    """Group byte-identical samples. Only the copies beyond the first count as redundant."""
    groups: list[DuplicateGroup] = []
    redundant = 0
    for digest, paths in sha_to_paths.items():
        if len(paths) > 1:
            groups.append(DuplicateGroup(hash=digest, filenames=sorted(paths), sample_count=len(paths)))
            redundant += len(paths) - 1
    groups.sort(key=lambda g: g.sample_count, reverse=True)
    return groups, redundant


def find_near_duplicates(
    fingerprints: Sequence[PerceptualFingerprint],
    embeddings: np.ndarray | None = None,
    embedding_index: dict[int, int] | None = None,
    contributors: dict[str, str] | None = None,
) -> DuplicateReport:
    """Two-stage near-duplicate search over a fingerprinted corpus.

    `embedding_index` maps a fingerprint's corpus index to its row in `embeddings`,
    because only a capped sample of a large corpus is embedded.
    """
    thresholds = SETTINGS.thresholds
    report = DuplicateReport()
    if len(fingerprints) < 2:
        return report

    # Stage 1: BK-tree radius query on pHash. Sublinear, so a 100k corpus is feasible.
    tree = BKTree()
    for fp in fingerprints:
        tree.add(fp.phash, fp.index)

    position = {fp.index: slot for slot, fp in enumerate(fingerprints)}
    seen_pairs: set[tuple[int, int]] = set()
    confirmed: list[tuple[int, int, int, float | None]] = []

    for fp in fingerprints:
        for other_index, distance in tree.query(fp.phash, thresholds.phash_hamming_max):
            if other_index == fp.index:
                continue
            key = (min(fp.index, other_index), max(fp.index, other_index))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            report.candidates_examined += 1

            a_slot = position[key[0]]
            b_slot = position[key[1]]
            fp_a, fp_b = fingerprints[a_slot], fingerprints[b_slot]

            # Byte-identical pairs are reported by the exact-duplicate path instead.
            if fp_a.sha256 == fp_b.sha256:
                continue

            # Stage 2: confirm in embedding space when we have features for both.
            cosine: float | None = None
            if embeddings is not None and embedding_index is not None and embeddings.size:
                row_a = embedding_index.get(key[0])
                row_b = embedding_index.get(key[1])
                if row_a is not None and row_b is not None:
                    cosine = float(np.dot(embeddings[row_a], embeddings[row_b]))
                    report.embedding_confirmed = True
                    if cosine < thresholds.embedding_cosine_min:
                        # pHash collision without semantic agreement -- a false positive,
                        # typically two different flat or low-texture scenes.
                        continue

            # A corroborating dHash check suppresses the remaining pHash collisions.
            if cosine is None and hamming(fp_a.dhash, fp_b.dhash) > thresholds.phash_hamming_max + 3:
                continue

            confirmed.append((key[0], key[1], distance, cosine))

    # Cluster the confirmed pairs so an analyst sees "one flood of 80" rather than
    # 3,160 unordered pairs.
    union = _UnionFind(len(fingerprints))
    for a_index, b_index, distance, cosine in confirmed:
        union.union(position[a_index], position[b_index])
        fp_a = fingerprints[position[a_index]]
        fp_b = fingerprints[position[b_index]]
        similarity = 1.0 - (distance / 64.0) if cosine is None else cosine
        report.near_pairs.append(
            NearDuplicatePair(
                sample_a=fp_a.path,
                sample_b=fp_b.path,
                hamming_distance=distance,
                cosine_similarity=cosine,
                similarity=similarity,
                contributor_a=(contributors or {}).get(fp_a.path),
                contributor_b=(contributors or {}).get(fp_b.path),
            )
        )

    clusters: dict[int, list[str]] = defaultdict(list)
    for slot, fp in enumerate(fingerprints):
        clusters[union.find(slot)].append(fp.path)
    real_clusters = [members for members in clusters.values() if len(members) > 1]
    real_clusters.sort(key=len, reverse=True)
    report.clusters = real_clusters
    # Every member beyond the first in a cluster is a redundant sample.
    report.near_duplicate_samples = sum(len(c) - 1 for c in real_clusters)

    # Attribute flooding to whoever supplied the redundant copies.
    if contributors:
        tally: dict[str, int] = defaultdict(int)
        for members in real_clusters:
            for path in members[1:]:
                owner = contributors.get(path)
                if owner:
                    tally[owner] += 1
        report.flooding_contributors = dict(sorted(tally.items(), key=lambda kv: kv[1], reverse=True))

    report.near_pairs.sort(key=lambda p: (p.hamming_distance, -p.similarity))
    return report


def summarise_hash_stats(fingerprints: Sequence[PerceptualFingerprint]) -> dict[str, Any]:
    """Corpus-level fingerprint statistics for the evidence panel."""
    if not fingerprints:
        return {"uniquePHashes": 0, "uniqueDHashes": 0, "sampleCount": 0}
    return {
        "sampleCount": len(fingerprints),
        "uniquePHashes": len({fp.phash for fp in fingerprints}),
        "uniqueDHashes": len({fp.dhash for fp in fingerprints}),
        "uniqueSha256": len({fp.sha256 for fp in fingerprints}),
        "examplePHash": hex_hash(fingerprints[0].phash),
    }


__all__ = [
    "DuplicateGroup",
    "DuplicateReport",
    "NearDuplicatePair",
    "find_exact_duplicates",
    "find_near_duplicates",
    "summarise_hash_stats",
]
