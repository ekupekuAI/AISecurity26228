"""Dataset integrity engine.

Orchestrates the full training-data workflow from the problem statement:

  ingest & digest -> format detection -> structural integrity -> perceptual dedup ->
  label-consistency cross-validation -> trigger screening -> OOD scoring ->
  contributor rollup -> risk & findings

Every stage is bounded and every stage that cannot run says so, because an assessment
that silently skipped its most important check is worse than no assessment at all. The
returned payload keeps the camelCase wire contract the console and gateway consume.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter, defaultdict
from typing import Any

import numpy as np

from analyzers import risk_engine
from analyzers.coverage import dataset_coverage
from core.config import SETTINGS
from core.models import make_finding, new_id, sort_findings, status_from_findings, utc_now
from ingest import contributors as contrib
from ingest.parsers import DatasetFormat, detect_and_parse, detect_split_leakage
from security.archive import ArchiveReport, iter_archive
from vision import duplicates as dup
from vision.embeddings import get_backbone
from vision.imaging import (
    DecodeFailure,
    DecodedImage,
    IMAGE_EXTENSIONS,
    decode_image,
    extension_mismatch,
)
from vision.label_noise import detect_label_noise
from vision.ood import detect_ood
from vision.phash import fingerprint
from vision.triggers import analyse_triggers

TEXT_EXTENSIONS = frozenset({".json", ".txt", ".csv", ".yaml", ".yml", ".names", ".xml"})


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _extension(path: str) -> str:
    return "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""


class DatasetAnalyzer:
    """Entry point for dataset assurance."""

    @classmethod
    def analyze(cls, filename: str, data: bytes) -> dict[str, Any]:
        started = time.perf_counter()
        archive_sha = _sha256(data)
        findings: list[dict[str, Any]] = []
        coverage_gaps: list[str] = []

        # --- stage 1: ingest -----------------------------------------------------
        archive_report = ArchiveReport()
        images: dict[str, bytes] = {}
        texts: dict[str, bytes] = {}
        other_files: list[str] = []

        if _extension(filename) in IMAGE_EXTENSIONS:
            images[filename] = data
            archive_report.format = "single-image"
            archive_report.entries_seen = 1
            archive_report.entries_yielded = 1
        else:
            for entry in iter_archive(data, archive_report):
                ext = _extension(entry.name)
                if ext in IMAGE_EXTENSIONS:
                    if len(images) < SETTINGS.limits.max_images_hashed:
                        images[entry.name] = entry.data
                elif ext in TEXT_EXTENSIONS:
                    texts[entry.name] = entry.data
                else:
                    other_files.append(entry.name)

        if archive_report.aborted:
            findings.append(
                make_finding(
                    finding_id="DS-ARCHIVE-ABORTED",
                    category="DATASET",
                    severity="CRITICAL",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        "Archive traversal was aborted by a resource guard: "
                        f"{archive_report.abort_reason}"
                    ),
                    evidence=archive_report.to_dict(),
                    recommendation=(
                        "Reject this submission. Require the contributor to resupply the corpus "
                        "within the declared size envelope."
                    ),
                    detector="security.archive.iter_archive",
                    threshold=(
                        f"total<= {SETTINGS.archive.max_total_uncompressed_bytes} B, "
                        f"ratio<= {SETTINGS.archive.max_compression_ratio}:1"
                    ),
                )
            )
            return cls._failed(filename, archive_sha, len(data), findings, archive_report, started)

        if archive_report.has_traversal_attempt:
            offenders = [
                v for v in archive_report.violations if v.kind in {"path-traversal", "absolute-path", "link-entry"}
            ]
            findings.append(
                make_finding(
                    finding_id="SEC-ARCHIVE-PATH-TRAVERSAL",
                    category="SUPPLY_CHAIN",
                    severity="CRITICAL",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        f"{len(offenders)} archive entries attempt to escape the extraction root "
                        "(Zip Slip) or are symbolic links. A benign export tool does not produce "
                        "these; the archive was deliberately crafted."
                    ),
                    evidence={"violations": [v.to_dict() for v in offenders[:20]]},
                    recommendation=(
                        "Quarantine the archive and revoke the contributor's ingest credentials. "
                        "Do not extract it on any node."
                    ),
                    detector="security.archive.is_unsafe_path",
                    threshold="any traversal component, absolute path, or link entry",
                    references=["CWE-22", "CWE-59"],
                )
            )

        compression_bombs = [v for v in archive_report.violations if v.kind == "compression-bomb"]
        if compression_bombs:
            findings.append(
                make_finding(
                    finding_id="SEC-ARCHIVE-COMPRESSION-BOMB",
                    category="SUPPLY_CHAIN",
                    severity="HIGH",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=(
                        f"{len(compression_bombs)} entries exceed the "
                        f"{SETTINGS.archive.max_compression_ratio:.0f}:1 expansion ceiling and were "
                        "refused. This is the signature of a decompression bomb aimed at the "
                        "ingest node."
                    ),
                    evidence={"entries": [v.to_dict() for v in compression_bombs[:20]]},
                    recommendation="Reject the archive and require an uncompressed manifest of its true contents.",
                    detector="security.archive.iter_archive",
                    threshold=f"uncompressed/compressed > {SETTINGS.archive.max_compression_ratio:.0f}",
                    references=["CWE-409"],
                )
            )

        if not images:
            # Recognise the single most common way this happens in practice: someone
            # uploads the raw CIFAR python download. Its batches are *pickle files*, and
            # this engine never unpickles submitted content -- that is the exact attack
            # surface the model scanner exists to close, and a dataset upload does not
            # get a more trusting deserialiser than a checkpoint does. So the batches
            # are refused, but the refusal should say what was recognised and what to
            # do, not shrug at the operator.
            names = [str(name).replace("\\", "/").rsplit("/", 1)[-1].lower() for name in other_files]
            cifar_batchlike = [
                name for name in names
                if name.startswith("data_batch") or name in {"test_batch", "batches.meta", "train", "test", "meta"}
            ]
            looks_like_cifar = len(cifar_batchlike) >= 3 or any(
                "cifar" in str(name).lower() for name in other_files
            )

            if looks_like_cifar:
                explanation = (
                    "No decodable image samples were found, but the entry names match the "
                    "CIFAR python distribution (data_batch_*, test_batch, batches.meta). "
                    "Those batches are Python pickle files, and this engine never unpickles "
                    "submitted content: deserialising attacker-supplied pickles is the exact "
                    "vulnerability class the checkpoint scanner exists to catch, and dataset "
                    "uploads are not granted a more trusting parser. Export the batches to "
                    "PNG or JPEG class folders and resubmit the corpus as images."
                )
                recommendation = (
                    "Convert the pickled batches to an image layout (one folder per class, "
                    "e.g. airplane/img_0001.png) on a trusted workstation and resubmit. "
                    "ml-engine/scripts/make_demo_assets.py performs exactly this conversion "
                    "for CIFAR-10."
                )
            else:
                explanation = (
                    "No decodable image samples were found. The submission is not a computer-"
                    "vision corpus in any recognised layout."
                )
                recommendation = "Return the submission to the contributor for re-export."

            findings.append(
                make_finding(
                    finding_id="DS-NO-SAMPLES",
                    category="DATASET",
                    severity="HIGH",
                    confidence=1.0,
                    affected_asset=filename,
                    explanation=explanation,
                    evidence={
                        "archive": archive_report.to_dict(),
                        "nonImageFiles": other_files[:20],
                        "textFiles": list(texts)[:20],
                        "recognisedAsCifarPythonBatches": looks_like_cifar,
                    },
                    recommendation=recommendation,
                    detector="analyzers.dataset_analyzer",
                    threshold="image count > 0",
                )
            )
            return cls._failed(filename, archive_sha, len(data), findings, archive_report, started)

        # --- stage 2: decode & structural integrity ------------------------------
        decoded: list[DecodedImage] = []
        failures: list[DecodeFailure] = []
        sha_to_paths: dict[str, list[str]] = defaultdict(list)
        mismatched: list[str] = []

        for path, payload in images.items():
            sha_to_paths[_sha256(payload)].append(path)
            result = decode_image(path, payload)
            if isinstance(result, DecodeFailure):
                failures.append(result)
                continue
            decoded.append(result)
            if extension_mismatch(result):
                mismatched.append(path)

        total_samples = len(images)

        if failures:
            by_reason = Counter(f.reason for f in failures)
            severity = "HIGH" if len(failures) / max(1, total_samples) > 0.02 else "MEDIUM"
            findings.append(
                make_finding(
                    finding_id="DS-CORRUPT-SAMPLES",
                    category="DATASET",
                    severity=severity,
                    confidence=0.99,
                    affected_asset=f"{len(failures)} of {total_samples} samples",
                    explanation=(
                        f"{len(failures)} samples ({len(failures) / max(1, total_samples):.1%}) could "
                        "not be decoded. Corrupt samples crash ingest pipelines and, when tolerated, "
                        "become an unbounded channel for non-image content."
                    ),
                    evidence={
                        "byReason": dict(by_reason),
                        "examples": [{"path": f.path, "reason": f.reason, "detail": f.detail} for f in failures[:12]],
                    },
                    recommendation="Purge the undecodable samples before ingest and query the contributor's export process.",
                    detector="vision.imaging.decode_image",
                    threshold="PIL structural verify + magic-byte match",
                )
            )

        if mismatched:
            findings.append(
                make_finding(
                    finding_id="DS-EXTENSION-MISMATCH",
                    category="DATASET",
                    severity="MEDIUM",
                    confidence=0.95,
                    affected_asset=f"{len(mismatched)} samples",
                    explanation=(
                        f"{len(mismatched)} samples declare one container in their filename and "
                        "contain another. Extension-trusting filters treat these as a different "
                        "format than the decoder will."
                    ),
                    evidence={"examples": mismatched[:15]},
                    recommendation="Normalise the corpus to a single declared format and re-export.",
                    detector="vision.imaging.extension_mismatch",
                    threshold="declared format != sniffed format",
                    references=["CWE-646"],
                )
            )

        # --- stage 3: layout & annotations ---------------------------------------
        layout = detect_and_parse(list(images), texts)
        labels_by_path = layout.labels
        if layout.defects:
            by_severity = Counter(d.severity for d in layout.defects)
            worst = "HIGH" if by_severity.get("HIGH") else "MEDIUM"
            findings.append(
                make_finding(
                    finding_id="DS-ANNOTATION-DEFECTS",
                    category="DATASET",
                    severity=worst,
                    confidence=0.97,
                    affected_asset=f"{layout.format.value} annotations",
                    explanation=(
                        f"{len(layout.defects)} structural defects in the annotation set: dangling "
                        "references, undeclared categories, duplicate ids or out-of-range "
                        "coordinates. Each either aborts training or silently drops supervision."
                    ),
                    evidence={
                        "format": layout.format.value,
                        "bySeverity": dict(by_severity),
                        "defects": [d.to_dict() for d in layout.defects[:25]],
                    },
                    recommendation="Return the annotation set for correction; do not auto-repair defence annotations.",
                    detector="ingest.parsers.detect_and_parse",
                    threshold="COCO/YOLO schema conformance",
                )
            )

        if layout.unlabelled_images and layout.format in {DatasetFormat.YOLO, DatasetFormat.COCO}:
            share = len(layout.unlabelled_images) / max(1, total_samples)
            if share > 0.05:
                findings.append(
                    make_finding(
                        finding_id="DS-UNLABELLED-SAMPLES",
                        category="DATASET",
                        severity="MEDIUM",
                        confidence=0.9,
                        affected_asset=f"{len(layout.unlabelled_images)} samples",
                        explanation=(
                            f"{share:.1%} of samples carry no annotation. In a detection corpus an "
                            "unlabelled image trains as pure background, which is a deniable way to "
                            "suppress recall for a specific class."
                        ),
                        evidence={"examples": layout.unlabelled_images[:15], "share": round(share, 4)},
                        recommendation="Confirm with the contributor whether these are intentional negatives.",
                        detector="ingest.parsers",
                        threshold="unlabelled share > 5%",
                    )
                )

        # --- stage 4: perceptual dedup -------------------------------------------
        exact_groups, exact_redundant = dup.find_exact_duplicates(dict(sha_to_paths))

        backbone = get_backbone()
        backbone_confidence = backbone.info.confidence_multiplier

        fingerprints = [
            fingerprint(index, image.path, image.gray, _sha256(images[image.path]))
            for index, image in enumerate(decoded)
        ]

        # Embed a deterministic, capped sample: sorting by path keeps the choice stable
        # across runs so two assessments of the same corpus agree exactly.
        embed_order = sorted(range(len(decoded)), key=lambda i: decoded[i].path)
        embed_order = embed_order[: SETTINGS.limits.max_images_embedded]
        embeddings = np.zeros((0, 512), dtype=np.float32)
        embedding_index: dict[int, int] = {}
        if backbone.available and embed_order:
            batch = np.stack([decoded[i].rgb_small for i in embed_order])
            embeddings = backbone.embed(batch)
            embedding_index = {i: row for row, i in enumerate(embed_order)}
        else:
            coverage_gaps.append("embedding-backbone-unavailable")

        contributor_of, attribution_strategy = contrib.resolve_contributors(list(images), texts)

        duplicate_report = dup.find_near_duplicates(
            fingerprints,
            embeddings=embeddings if embeddings.size else None,
            embedding_index=embedding_index or None,
            contributors=contributor_of,
        )
        duplicate_report.exact_groups = exact_groups
        duplicate_report.exact_duplicate_samples = exact_redundant

        redundant_total = duplicate_report.total_redundant_samples
        if redundant_total:
            share = redundant_total / max(1, total_samples)
            flooding = share >= SETTINGS.thresholds.duplicate_flood_ratio
            findings.append(
                make_finding(
                    finding_id="DS-DUPLICATE-FLOODING" if flooding else "DS-REDUNDANT-SAMPLES",
                    category="DATASET",
                    severity="HIGH" if flooding else "MEDIUM",
                    confidence=0.99 if exact_redundant else 0.9,
                    affected_asset=f"{redundant_total} redundant samples",
                    explanation=(
                        f"{redundant_total} samples ({share:.1%}) are exact or perceptual duplicates of "
                        f"another sample: {exact_redundant} byte-identical and "
                        f"{duplicate_report.near_duplicate_samples} near-identical. "
                        + (
                            "This exceeds the flooding threshold, which inflates a contributor's "
                            "apparent share of the corpus and biases the trained model toward it."
                            if flooding
                            else "Deduplicate before training to avoid memorisation."
                        )
                    ),
                    evidence=duplicate_report.to_dict(),
                    recommendation=(
                        "Deduplicate the corpus and audit the flooding contributor's submission history."
                        if flooding
                        else "Deduplicate the corpus before ingest."
                    ),
                    detector="vision.duplicates.find_near_duplicates",
                    threshold=(
                        f"pHash Hamming <= {SETTINGS.thresholds.phash_hamming_max}"
                        + (
                            f" AND embedding cosine > {SETTINGS.thresholds.embedding_cosine_min}"
                            if duplicate_report.embedding_confirmed
                            else " (embedding confirmation unavailable)"
                        )
                    ),
                )
            )

        leaks = detect_split_leakage(labels_by_path, duplicate_report.clusters + [g.filenames for g in exact_groups])
        if leaks:
            findings.append(
                make_finding(
                    finding_id="DS-SPLIT-LEAKAGE",
                    category="DATASET",
                    severity="HIGH",
                    confidence=0.96,
                    affected_asset=f"{len(leaks)} duplicate clusters spanning splits",
                    explanation=(
                        f"{len(leaks)} duplicate clusters contain samples in more than one split. "
                        "Any accuracy measured on that held-out split is contaminated and cannot be "
                        "used to certify the model."
                    ),
                    evidence={"leaks": leaks[:15]},
                    recommendation="Rebuild the splits after deduplication and re-measure held-out accuracy.",
                    detector="ingest.parsers.detect_split_leakage",
                    threshold="duplicate cluster spanning >1 split directory",
                )
            )

        # --- stage 5: label consistency ------------------------------------------
        embedded_paths = [decoded[i].path for i in embed_order]
        embedded_labels = [labels_by_path.get(path, "unlabelled") for path in embedded_paths]

        label_report = detect_label_noise(embeddings, embedded_labels, embedded_paths, backbone_confidence)
        if not label_report.available:
            coverage_gaps.append("label-consistency-not-run")
        if label_report.suspects:
            severity = "HIGH" if label_report.systematic else "MEDIUM"
            findings.append(
                make_finding(
                    finding_id="DS-LABEL-FLIPPING" if label_report.systematic else "DS-LABEL-NOISE",
                    category="DATASET",
                    severity=severity,
                    confidence=min(0.95, 0.6 + 0.35 * backbone_confidence),
                    affected_asset=f"{len(label_report.suspects)} samples",
                    explanation=(
                        f"{len(label_report.suspects)} samples sit inside another class's embedding "
                        f"neighbourhood ({label_report.noise_rate:.1%} of those analysed). "
                        + label_report.systematic_explanation
                    ),
                    evidence=label_report.to_dict(),
                    recommendation=(
                        "Quarantine the implicated contributor's annotations and re-label under "
                        "multi-analyst consensus."
                        if label_report.systematic
                        else "Route the flagged samples for annotation review."
                    ),
                    detector="vision.label_noise.detect_label_noise",
                    threshold=(
                        f"k={SETTINGS.thresholds.knn_neighbours} neighbour disagreement >= "
                        f"{SETTINGS.thresholds.label_disagreement_min:.0%} and margin >= "
                        f"{SETTINGS.thresholds.label_margin_min:.0%}"
                    ),
                    references=["Northcutt et al., Confident Learning (JAIR 2021)"],
                )
            )

        # --- stage 6: trigger screening ------------------------------------------
        analysis_images = np.stack([decoded[i].rgb_small for i in embed_order]) if embed_order else np.zeros((0, 64, 64, 3), np.uint8)
        analysis_grays = [decoded[i].gray for i in embed_order]
        analysis_sizes = [(decoded[i].width, decoded[i].height) for i in embed_order]

        trigger_report = analyse_triggers(
            analysis_images, analysis_grays, embedded_labels, embedded_paths, analysis_sizes
        )

        if trigger_report.clusters:
            confirmed = trigger_report.confirmed_samples
            findings.append(
                make_finding(
                    finding_id="DS-BACKDOOR-TRIGGER-INJECTION",
                    category="DATASET",
                    severity="CRITICAL",
                    confidence=min(0.97, max(c.consistency for c in trigger_report.clusters)),
                    affected_asset=f"{confirmed} samples across {len(trigger_report.clusters)} trigger cluster(s)",
                    explanation=(
                        f"{confirmed} samples carry an identical perturbation at an identical location. "
                        "Spatial consistency across independent samples is the functional requirement "
                        "of a backdoor trigger and does not occur in natural imagery. The recovered "
                        "trigger pattern is attached as evidence."
                    ),
                    evidence={
                        "clusters": [c.to_dict() for c in trigger_report.clusters[:6]],
                        "targetLabels": sorted({c.label for c in trigger_report.clusters}),
                    },
                    recommendation=(
                        "QUARANTINE the corpus. Revoke the contributing source's ingest pipeline and "
                        "retrain any model that consumed this data from a clean checkpoint."
                    ),
                    detector="vision.triggers.find_consensus_triggers",
                    threshold="modified z-score > 3.0 on residual peak, >=3 samples agreeing within 6px",
                    references=["Gu et al., BadNets (2017)", "Chen et al., Blended attack (2017)"],
                )
            )
        elif trigger_report.candidates:
            findings.append(
                make_finding(
                    finding_id="DS-TRIGGER-CANDIDATES",
                    category="DATASET",
                    severity="MEDIUM",
                    confidence=0.5,
                    affected_asset=f"{len(trigger_report.candidates)} samples",
                    explanation=(
                        f"{len(trigger_report.candidates)} samples show localised high-frequency or "
                        "high-variance artifacts, but no cross-sample consensus was found. These are "
                        "candidates for manual review, not confirmed triggers -- compression artifacts "
                        "and overlaid text produce the same single-image signature."
                    ),
                    evidence=trigger_report.to_dict(),
                    recommendation="Visually review the flagged regions before drawing a conclusion.",
                    detector="vision.triggers.screen_image",
                    threshold=(
                        f"high-frequency z >= {SETTINGS.thresholds.trigger_highfreq_z} AND local variance "
                        f"ratio >= {SETTINGS.thresholds.trigger_patch_variance_ratio}"
                    ),
                )
            )

        # --- stage 7: OOD ---------------------------------------------------------
        ood_report = detect_ood(embeddings, embedded_labels, embedded_paths, backbone_confidence)
        if not ood_report.available:
            coverage_gaps.append("ood-not-run")
        if ood_report.outliers:
            findings.append(
                make_finding(
                    finding_id="DS-OUT-OF-DISTRIBUTION",
                    category="DATASET",
                    severity="MEDIUM",
                    confidence=min(0.9, 0.55 + 0.35 * backbone_confidence),
                    affected_asset=f"{len(ood_report.outliers)} samples",
                    explanation=(
                        f"{len(ood_report.outliers)} samples lie beyond the "
                        f"{SETTINGS.thresholds.ood_mahalanobis_percentile:.0f}th percentile of "
                        "Mahalanobis distance to their nearest class centroid. These are the corpus's "
                        "blind spots: content the trained model will be asked to handle but was never "
                        "meaningfully supervised on."
                    ),
                    evidence=ood_report.to_dict(),
                    recommendation="Review the outliers for domain relevance; remove padding content and cover genuine gaps.",
                    detector="vision.ood.detect_ood",
                    threshold=f"Mahalanobis distance > P{SETTINGS.thresholds.ood_mahalanobis_percentile:.0f} of corpus",
                    references=["Lee et al., A Simple Unified Framework for Detecting OOD Samples (NeurIPS 2018)"],
                )
            )

        # --- stage 8: class balance ----------------------------------------------
        class_distribution = Counter(labels_by_path.values())
        imbalance_ratio = 1.0
        if len(class_distribution) > 1:
            counts = list(class_distribution.values())
            imbalance_ratio = max(counts) / max(1, min(counts))
            if imbalance_ratio > 8.0:
                findings.append(
                    make_finding(
                        finding_id="DS-CLASS-IMBALANCE",
                        category="DATASET",
                        severity="MEDIUM" if imbalance_ratio < 25 else "HIGH",
                        confidence=1.0,
                        affected_asset="class distribution",
                        explanation=(
                            f"Class distribution is skewed {imbalance_ratio:.1f}:1 between the largest "
                            "and smallest class. Severe skew produces a model that appears accurate "
                            "overall while failing on the minority class."
                        ),
                        evidence={"classDistribution": dict(class_distribution)},
                        recommendation="Rebalance by collection or apply class-weighted training, and re-evaluate per-class recall.",
                        detector="analyzers.dataset_analyzer",
                        threshold="max/min class count > 8:1",
                    )
                )

        # --- stage 9: contributor rollup ------------------------------------------
        trigger_paths = {c.path for c in trigger_report.candidates if "consensus" in c.method.lower()}
        exact_dup_paths = {p for group in exact_groups for p in group.filenames[1:]}
        near_dup_paths = {p for cluster in duplicate_report.clusters for p in cluster[1:]}

        profiles = contrib.aggregate(
            contributor_of,
            exact_duplicate_paths=exact_dup_paths,
            near_duplicate_paths=near_dup_paths,
            label_suspect_paths=[s.path for s in label_report.suspects],
            trigger_paths=trigger_paths,
            ood_paths=[o.path for o in ood_report.outliers],
            corrupt_paths=[f.path for f in failures],
        )

        for profile in profiles:
            if profile.risk_score >= 60.0 and profile.sample_count >= 20:
                findings.append(
                    make_finding(
                        finding_id="DS-CONTRIBUTOR-RISK",
                        category="DATASET",
                        severity="HIGH",
                        confidence=0.88,
                        affected_asset=f"Contributor: {profile.name}",
                        explanation=(
                            f"Source '{profile.name}' supplied {profile.sample_count} samples with a "
                            f"{profile.defect_density:.1%} defect density, yielding a source risk of "
                            f"{profile.risk_score:.0f}/100. Attribution strategy: {attribution_strategy}."
                        ),
                        evidence=profile.to_dict(),
                        recommendation=(
                            f"Suspend ingest from '{profile.name}' pending a supply-chain review of "
                            "their collection and annotation process."
                        ),
                        detector="ingest.contributors.aggregate",
                        threshold="source risk >= 60 with >= 20 samples",
                    )
                )

        # --- stage 10: score -------------------------------------------------------
        finding_risk = risk_engine.findings_risk(findings)
        risk, breakdown = risk_engine.dataset_risk(
            total_samples=total_samples,
            corrupt_count=len(failures),
            redundant_count=redundant_total,
            label_suspect_count=len(label_report.suspects),
            label_noise_is_systematic=label_report.systematic,
            trigger_confirmed_count=trigger_report.confirmed_samples,
            ood_count=len(ood_report.outliers),
            annotation_defects=len(layout.defects),
            class_imbalance_ratio=imbalance_ratio,
            finding_risk=finding_risk,
        )

        findings = sort_findings(findings)
        elapsed = time.perf_counter() - started

        return {
            "id": new_id("DS"),
            "filename": filename,
            "sha256": archive_sha,
            "fileSizeBytes": len(data),
            "totalSamples": total_samples,
            "decodedSamples": len(decoded),
            "corruptedFiles": len(failures),
            "corruptSampleDetails": [
                {"path": f.path, "reason": f.reason, "detail": f.detail} for f in failures[:25]
            ],
            "format": layout.format.value,
            "layout": layout.to_dict(),
            "archive": archive_report.to_dict(),
            "duplicateFiles": [g.to_dict() for g in exact_groups[:50]],
            "nearDuplicateCandidates": [p.to_dict() for p in duplicate_report.near_pairs[:50]],
            "duplicateAnalysis": duplicate_report.to_dict(),
            "hashStats": dup.summarise_hash_stats(fingerprints),
            "classDistribution": dict(class_distribution),
            "classImbalanceRatio": round(imbalance_ratio, 2),
            "labelAnalysis": label_report.to_dict(),
            "suspiciousLabelPatterns": (
                [label_report.systematic_explanation] if label_report.suspects else []
            ),
            "triggerAnalysis": trigger_report.to_dict(),
            "anomalousSamples": [
                {
                    "filename": c.path,
                    "reason": f"{c.method}: localised perturbation at {list(c.bbox)}",
                    "anomalyScore": round(c.score, 3),
                    "metric": (
                        f"high-frequency z={c.high_freq_z:.2f}, patch variance ratio="
                        f"{c.patch_variance_ratio:.2f}"
                    ),
                    "bbox": list(c.bbox),
                }
                for c in trigger_report.candidates[:25]
            ],
            "oodAnalysis": ood_report.to_dict(),
            "oodIndicators": (
                [
                    f"{len(ood_report.outliers)} samples beyond the "
                    f"P{SETTINGS.thresholds.ood_mahalanobis_percentile:.0f} Mahalanobis threshold."
                ]
                if ood_report.outliers
                else []
            ),
            "contributorStats": {p.name: p.sample_count for p in profiles},
            "contributorProfiles": [p.to_dict() for p in profiles],
            "contributorAttributionStrategy": attribution_strategy,
            "backbone": backbone.info.to_dict(),
            "coverage": [entry.to_dict() for entry in dataset_coverage(backbone.info, layout, trigger_report)],
            "coverageGaps": coverage_gaps,
            "riskBreakdown": breakdown,
            "datasetRisk": risk,
            "status": status_from_findings(findings),
            "findings": findings,
            "analysisDurationSeconds": round(elapsed, 3),
            "engine": "python-full",
            "timestamp": utc_now(),
        }

    @staticmethod
    def _failed(
        filename: str,
        sha: str,
        size: int,
        findings: list[dict[str, Any]],
        archive_report: ArchiveReport,
        started: float,
    ) -> dict[str, Any]:
        return {
            "id": new_id("DS"),
            "filename": filename,
            "sha256": sha,
            "fileSizeBytes": size,
            "totalSamples": 0,
            "decodedSamples": 0,
            "corruptedFiles": 0,
            "format": "UNKNOWN",
            "archive": archive_report.to_dict(),
            "duplicateFiles": [],
            "nearDuplicateCandidates": [],
            "classDistribution": {},
            "suspiciousLabelPatterns": [],
            "anomalousSamples": [],
            "oodIndicators": [],
            "contributorStats": {},
            "contributorProfiles": [],
            "coverage": [],
            "coverageGaps": ["analysis-aborted"],
            "datasetRisk": 100.0,
            "status": "ANALYSIS FAILED",
            "findings": sort_findings(findings),
            "analysisDurationSeconds": round(time.perf_counter() - started, 3),
            "engine": "python-full",
            "timestamp": utc_now(),
        }


__all__ = ["DatasetAnalyzer"]
