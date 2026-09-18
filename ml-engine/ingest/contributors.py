"""Contributor attribution and source-level risk aggregation.

The problem statement asks for evidence to be rolled up "to source-level risk
assessments". That is the operationally useful output: an analyst cannot adjudicate
10,000 individual samples, but they can revoke one contributor's ingest pipeline.

Attribution is resolved in priority order, most explicit first:

1. A manifest (``contributors.csv``, ``manifest.csv``, ``provenance.json``) mapping
   sample paths to a source identity.
2. A top-level directory that names a contributor (``contributor_b/``, ``vendor-3/``,
   ``source_alpha/``).
3. The top-level directory itself, when the archive is partitioned that way.
4. A single implicit contributor, when the archive carries no structure at all.

Defect *density* rather than raw count is what drives the score: a contributor supplying
8,000 samples with 40 defects is in far better shape than one supplying 200 with 40, and
scoring on counts alone would invert that.
"""

from __future__ import annotations

import csv
import io
import json
import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

#: Directory names that read as a contributor identity rather than a data split.
_CONTRIBUTOR_HINT = re.compile(
    r"^(contributor|vendor|supplier|source|partner|agency|unit|batch|node|team|org)[-_ ]?([a-z0-9]+)$",
    re.IGNORECASE,
)

#: Directory names that are structural, never a contributor.
_STRUCTURAL = frozenset(
    {
        "train", "training", "val", "valid", "validation", "test", "eval", "holdout",
        "images", "image", "img", "imgs", "labels", "label", "annotations", "anno",
        "data", "dataset", "raw", "processed", "jpegimages", "jpeg", "png", "masks",
    }
)

MANIFEST_NAMES = frozenset(
    {"contributors.csv", "manifest.csv", "sources.csv", "provenance.json", "contributors.json", "manifest.json"}
)


@dataclass
class ContributorProfile:
    """Per-source rollup. `risk_score` is 0-100, higher is worse."""

    name: str
    sample_count: int = 0
    exact_duplicates: int = 0
    near_duplicates: int = 0
    label_suspects: int = 0
    trigger_samples: int = 0
    ood_samples: int = 0
    corrupt_samples: int = 0
    annotation_defects: int = 0
    risk_score: float = 0.0
    defect_density: float = 0.0
    drivers: list[str] = field(default_factory=list)

    @property
    def total_defects(self) -> int:
        return (
            self.exact_duplicates
            + self.near_duplicates
            + self.label_suspects
            + self.trigger_samples
            + self.ood_samples
            + self.corrupt_samples
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "sampleCount": self.sample_count,
            "exactDuplicates": self.exact_duplicates,
            "nearDuplicates": self.near_duplicates,
            "labelSuspects": self.label_suspects,
            "triggerSamples": self.trigger_samples,
            "oodSamples": self.ood_samples,
            "corruptSamples": self.corrupt_samples,
            "annotationDefects": self.annotation_defects,
            "totalDefects": self.total_defects,
            "defectDensityPercent": round(self.defect_density * 100.0, 3),
            "riskScore": round(self.risk_score, 1),
            "riskDrivers": self.drivers,
        }


def resolve_contributors(image_paths: Iterable[str], text_files: dict[str, bytes]) -> tuple[dict[str, str], str]:
    """Map each sample path to a contributor. Returns (mapping, strategy-used)."""
    paths = list(image_paths)

    manifest_map = _from_manifest(text_files)
    if manifest_map:
        resolved = {path: manifest_map[_basename(path)] for path in paths if _basename(path) in manifest_map}
        if len(resolved) >= max(1, len(paths) // 2):
            for path in paths:
                resolved.setdefault(path, "UNATTRIBUTED")
            return resolved, "manifest"

    hinted = {}
    for path in paths:
        name = _hinted_directory(path)
        if name:
            hinted[path] = name
    if len(hinted) >= max(1, len(paths) // 2):
        for path in paths:
            hinted.setdefault(path, "UNATTRIBUTED")
        return hinted, "directory-name-hint"

    top_level = {path: _top_level(path) for path in paths}
    distinct = {value for value in top_level.values() if value not in {"", "UNATTRIBUTED"}}
    if 2 <= len(distinct) <= 64 and not distinct <= _STRUCTURAL:
        return top_level, "top-level-partition"

    return {path: "SINGLE_SOURCE" for path in paths}, "single-source"


def _basename(path: str) -> str:
    return posixpath.basename(path.replace("\\", "/"))


def _top_level(path: str) -> str:
    parts = path.replace("\\", "/").lstrip("./").split("/")
    if len(parts) < 2:
        return "UNATTRIBUTED"
    head = parts[0]
    return "UNATTRIBUTED" if head.lower() in _STRUCTURAL else head


def _hinted_directory(path: str) -> str | None:
    for part in path.replace("\\", "/").split("/")[:-1]:
        match = _CONTRIBUTOR_HINT.match(part)
        if match:
            return part
    return None


def _from_manifest(text_files: dict[str, bytes]) -> dict[str, str]:
    """Read a contributor manifest if the archive ships one."""
    mapping: dict[str, str] = {}
    for name, blob in text_files.items():
        if _basename(name).lower() not in MANIFEST_NAMES:
            continue
        try:
            text = blob.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue

        if name.lower().endswith(".json"):
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                continue
            entries = document if isinstance(document, list) else document.get("samples") or document.get("files") or []
            if isinstance(document, dict) and not entries:
                # Flat {"file.jpg": "Contributor A"} shape.
                for key, value in document.items():
                    if isinstance(value, str):
                        mapping[_basename(key)] = value
            for entry in entries if isinstance(entries, list) else []:
                if not isinstance(entry, dict):
                    continue
                file_key = entry.get("file") or entry.get("filename") or entry.get("path")
                source = entry.get("contributor") or entry.get("source") or entry.get("vendor") or entry.get("agency")
                if file_key and source:
                    mapping[_basename(str(file_key))] = str(source)
            continue

        try:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                lowered = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
                file_key = lowered.get("file") or lowered.get("filename") or lowered.get("path") or lowered.get("image")
                source = (
                    lowered.get("contributor")
                    or lowered.get("source")
                    or lowered.get("vendor")
                    or lowered.get("agency")
                    or lowered.get("supplier")
                )
                if file_key and source:
                    mapping[_basename(file_key)] = source
        except csv.Error:
            continue

    return mapping


def aggregate(
    contributor_of: dict[str, str],
    *,
    exact_duplicate_paths: Iterable[str] = (),
    near_duplicate_paths: Iterable[str] = (),
    label_suspect_paths: Iterable[str] = (),
    trigger_paths: Iterable[str] = (),
    ood_paths: Iterable[str] = (),
    corrupt_paths: Iterable[str] = (),
    annotation_defect_paths: Iterable[str] = (),
) -> list[ContributorProfile]:
    """Roll sample-level flags up to per-contributor risk profiles."""
    profiles: dict[str, ContributorProfile] = defaultdict(lambda: ContributorProfile(name="?"))

    for path, owner in contributor_of.items():
        profile = profiles[owner]
        profile.name = owner
        profile.sample_count += 1

    def tally(paths: Iterable[str], attribute: str) -> None:
        for path in paths:
            owner = contributor_of.get(path)
            if owner is None:
                continue
            profile = profiles[owner]
            profile.name = owner
            setattr(profile, attribute, getattr(profile, attribute) + 1)

    tally(exact_duplicate_paths, "exact_duplicates")
    tally(near_duplicate_paths, "near_duplicates")
    tally(label_suspect_paths, "label_suspects")
    tally(trigger_paths, "trigger_samples")
    tally(ood_paths, "ood_samples")
    tally(corrupt_paths, "corrupt_samples")
    tally(annotation_defect_paths, "annotation_defects")

    results = []
    for profile in profiles.values():
        _score(profile)
        results.append(profile)

    results.sort(key=lambda p: (-p.risk_score, -p.sample_count))
    return results


def _score(profile: ContributorProfile) -> None:
    """Weighted defect density, scaled by how much evidence we have about the source.

    Weights reflect adversarial intent, not just data hygiene: a trigger is a weapon, a
    duplicate is usually laziness. The small-sample damping stops a contributor with
    three samples and one defect from topping the table.
    """
    total = max(1, profile.sample_count)

    weighted = (
        profile.trigger_samples * 5.0
        + profile.label_suspects * 3.0
        + profile.corrupt_samples * 1.5
        + profile.near_duplicates * 1.0
        + profile.exact_duplicates * 1.0
        + profile.ood_samples * 0.75
        + profile.annotation_defects * 0.5
    )
    density = weighted / total
    profile.defect_density = profile.total_defects / total

    # Soft saturation rather than a hard clip. A hard clip flattens every seriously
    # defective source to the same 100, after which the small-sample damping below
    # decides the ranking -- which would rank a large sloppy source above a small
    # actively hostile one. An exponential keeps the ordering meaningful across the
    # whole range.
    import math

    base = 100.0 * (1.0 - math.exp(-density / 0.35))

    # Damp small samples: with 10 images we do not know enough to condemn a source. The
    # damping is deliberately mild so it can shade a ranking but never invert one.
    evidence = min(1.0, total / 50.0)
    score = base * (0.7 + 0.3 * evidence)

    # A confirmed backdoor trigger is categorical, not statistical. A source shipping
    # weaponised samples outranks any amount of ordinary sloppiness regardless of how
    # few samples it supplied.
    if profile.trigger_samples > 0:
        trigger_share = profile.trigger_samples / total
        score = max(score, 70.0 + min(25.0, trigger_share * 25.0))

    profile.risk_score = min(100.0, score)

    drivers: list[str] = []
    if profile.trigger_samples:
        drivers.append(
            f"{profile.trigger_samples} sample(s) carrying backdoor trigger artifacts "
            f"({profile.trigger_samples / total:.1%} of this source)"
        )
    if profile.label_suspects:
        drivers.append(
            f"{profile.label_suspects} label-consistency failure(s) ({profile.label_suspects / total:.1%})"
        )
    if profile.exact_duplicates or profile.near_duplicates:
        drivers.append(
            f"{profile.exact_duplicates + profile.near_duplicates} redundant sample(s) from duplicate flooding"
        )
    if profile.corrupt_samples:
        drivers.append(f"{profile.corrupt_samples} undecodable or corrupt sample(s)")
    if profile.ood_samples:
        drivers.append(f"{profile.ood_samples} out-of-distribution sample(s)")
    if profile.annotation_defects:
        drivers.append(f"{profile.annotation_defects} annotation defect(s)")
    if not drivers:
        drivers.append("No defects attributed to this source.")
    if total < 50:
        drivers.append(
            f"Score damped: only {total} sample(s) from this source, which is too few for a "
            "confident source-level judgement."
        )

    profile.drivers = drivers


__all__ = ["ContributorProfile", "aggregate", "resolve_contributors"]
