"""Dataset engine tests.

Each test asserts on a *detector outcome*, not on a score, so a change to the weighting
scheme does not silently break the meaning of the suite.
"""

from __future__ import annotations

import numpy as np
import pytest

from analyzers.dataset_analyzer import DatasetAnalyzer
from ingest.parsers import DatasetFormat, detect_and_parse
from tests.conftest import build_zip, make_image, png_bytes, stamp_trigger
from vision.duplicates import find_near_duplicates
from vision.ood import detect_ood
from vision.phash import BKTree, ahash, dhash, hamming, phash
from vision.triggers import find_consensus_triggers, high_frequency_ratio


def finding_ids(result: dict) -> set[str]:
    return {f["findingId"] for f in result["findings"]}


class TestPerceptualHashing:
    def test_identical_images_hash_identically(self) -> None:
        gray = make_image(1)[:, :, 0].astype(np.float32)
        assert phash(gray) == phash(gray)
        assert dhash(gray) == dhash(gray)
        assert ahash(gray) == ahash(gray)

    def test_rescaled_image_stays_within_hamming_radius(self) -> None:
        """The property that makes pHash useful: survives resampling."""
        from PIL import Image

        original = make_image(7, size=128)[:, :, 0].astype(np.float32)
        shrunk = np.asarray(
            Image.fromarray(original.astype(np.uint8)).resize((96, 96), Image.Resampling.BILINEAR).resize(
                (128, 128), Image.Resampling.BILINEAR
            ),
            dtype=np.float32,
        )

        assert hamming(phash(original), phash(shrunk)) <= 5

    def test_distinct_images_are_far_apart(self) -> None:
        a = make_image(3, base=0.2)[:, :, 0].astype(np.float32)
        b = make_image(400, base=0.8)[:, :, 0].astype(np.float32)

        assert hamming(phash(a), phash(b)) > 5

    def test_bktree_radius_query_matches_bruteforce(self) -> None:
        rng = np.random.default_rng(3)
        values = [int(rng.integers(0, 2**63)) for _ in range(300)]
        tree = BKTree()
        for index, value in enumerate(values):
            tree.add(value, index)

        probe = values[17]
        found = {index for index, _ in tree.query(probe, 8)}
        expected = {i for i, v in enumerate(values) if hamming(probe, v) <= 8}

        assert expected <= found


class TestDuplicateDetection:
    def test_near_duplicates_cluster_and_attribute(self) -> None:
        from vision.phash import fingerprint

        base = make_image(11)[:, :, 0].astype(np.float32)
        fingerprints = [
            fingerprint(0, "contributor_b/a.png", base, "sha-a"),
            fingerprint(1, "contributor_b/b.png", base + 0.5, "sha-b"),
            fingerprint(2, "contributor_a/other.png", make_image(900, base=0.9)[:, :, 0].astype(np.float32), "sha-c"),
        ]
        contributors = {
            "contributor_b/a.png": "Contributor_B",
            "contributor_b/b.png": "Contributor_B",
            "contributor_a/other.png": "Contributor_A",
        }

        report = find_near_duplicates(fingerprints, contributors=contributors)

        assert report.near_duplicate_samples >= 1
        assert report.flooding_contributors.get("Contributor_B", 0) >= 1
        assert "Contributor_A" not in report.flooding_contributors


class TestTriggerDetection:
    def test_high_frequency_ratio_rises_with_a_patch(self) -> None:
        clean = make_image(5, size=128)[:, :, 0].astype(np.float32)
        poisoned = stamp_trigger(make_image(5, size=128), size=16)[:, :, 0].astype(np.float32)

        assert high_frequency_ratio(poisoned) > high_frequency_ratio(clean)

    def test_consensus_recovers_a_shared_trigger(self) -> None:
        """The core claim: a trigger is detected because it is *shared*, not because it is odd."""
        images = []
        labels = []
        paths = []
        for i in range(24):
            images.append(make_image(i, size=64, base=0.5))
            labels.append("target")
            paths.append(f"clean/{i}.png")
        for i in range(8):
            images.append(stamp_trigger(make_image(500 + i, size=64, base=0.5)))
            labels.append("target")
            paths.append(f"poisoned/{i}.png")

        clusters = find_consensus_triggers(np.stack(images), labels, paths)

        assert clusters, "a shared corner trigger across 8 samples must form a cluster"
        top = clusters[0]
        poisoned_members = [p for p in top.member_paths if p.startswith("poisoned/")]
        assert len(poisoned_members) >= 5
        assert top.consistency > 0.35
        assert top.recovered_patch_rgb, "the trigger pattern itself must be recovered as evidence"

    def test_clean_corpus_yields_no_cluster(self) -> None:
        images = [make_image(i, size=64) for i in range(30)]
        labels = ["a"] * 30
        paths = [f"clean/{i}.png" for i in range(30)]

        clusters = find_consensus_triggers(np.stack(images), labels, paths)

        assert clusters == []


class TestOutOfDistribution:
    """Mahalanobis OOD scoring on embeddings directly, so it needs no staged backbone.

    OOD imagery -- a different sensor, a padded domain -- is a defence blind spot, not mere
    noise. The detector must surface samples that sit far from every class distribution and
    attribute them, while leaving the in-distribution bulk alone.
    """

    def test_far_samples_are_flagged_and_attributed(self) -> None:
        rng = np.random.default_rng(11)
        dim = 64
        rows: list[np.ndarray] = []
        labels: list[str] = []
        paths: list[str] = []

        # Two tight in-distribution clusters at well-separated centroids. The corpus is large
        # because the detector flags only the 99th-percentile tail by design, so 1% of the
        # corpus must comfortably exceed the number of injected outliers.
        for label, centre in (("vehicle", np.zeros(dim)), ("personnel", np.full(dim, 3.0))):
            for i in range(250):
                rows.append(centre + rng.normal(0.0, 0.1, dim))
                labels.append(label)
                paths.append(f"{label}/in_{i}.png")

        # A realistic handful (~1% of the class) of genuinely out-of-distribution samples,
        # labelled vehicle but far from every class. A large contaminated fraction would mask
        # itself by inflating its own class covariance -- that is a property of the estimator,
        # not the test.
        ood_paths: list[str] = []
        for i in range(3):
            rows.append(np.full(dim, 40.0) + rng.normal(0.0, 0.1, dim))
            labels.append("vehicle")
            path = f"vehicle/ood_{i}.png"
            paths.append(path)
            ood_paths.append(path)

        report = detect_ood(np.stack(rows).astype(np.float32), labels, paths)

        assert report.available
        flagged = {o.path for o in report.outliers}
        assert set(ood_paths) <= flagged, sorted(flagged)
        assert report.per_class_outliers.get("vehicle", 0) >= 3

    def test_homogeneous_corpus_reports_no_wild_outliers(self) -> None:
        """The negative control: a clean, single-distribution corpus is not condemned."""
        rng = np.random.default_rng(5)
        dim = 64
        rows = [rng.normal(0.0, 0.1, dim) for _ in range(120)]
        labels = ["vehicle"] * 60 + ["personnel"] * 60
        paths = [f"c/{i}.png" for i in range(120)]

        report = detect_ood(np.stack(rows).astype(np.float32), labels, paths)

        assert report.available
        # A tight homogeneous corpus should not flag more than the top-percentile tail.
        assert len(report.outliers) <= 6


class TestParsers:
    def test_coco_defects_are_enumerated(self, coco_dataset_zip: bytes) -> None:
        result = DatasetAnalyzer.analyze("coco.zip", coco_dataset_zip)

        assert result["format"] == DatasetFormat.COCO.value
        kinds = {d["kind"] for d in result["layout"]["defects"]}
        assert "dangling-annotation" in kinds
        assert "undeclared-category" in kinds
        assert "invalid-bbox" in kinds
        assert "DS-ANNOTATION-DEFECTS" in finding_ids(result)

    def test_yolo_layout_and_range_checks(self) -> None:
        entries: dict[str, bytes] = {}
        for i in range(6):
            entries[f"images/train/frame_{i}.png"] = png_bytes(make_image(i))
            entries[f"labels/train/frame_{i}.txt"] = b"0 0.5 0.5 0.2 0.2\n"
        entries["labels/train/frame_0.txt"] = b"0 1.7 0.5 0.2 0.2\n"  # out of range
        entries["data.yaml"] = b"names: [vehicle, personnel]\nnc: 2\n"

        layout = detect_and_parse(
            [name for name in entries if name.endswith(".png")],
            {name: data for name, data in entries.items() if not name.endswith(".png")},
        )

        assert layout.format == DatasetFormat.YOLO
        assert layout.class_names == ["vehicle", "personnel"]
        assert any(d.kind == "coordinates-out-of-range" for d in layout.defects)

    def test_image_folder_labels_from_directories(self) -> None:
        layout = detect_and_parse(["train/vehicle/a.png", "train/personnel/b.png"], {})

        assert layout.format == DatasetFormat.IMAGE_FOLDER
        assert layout.labels["train/vehicle/a.png"] == "vehicle"


class TestDatasetAnalyzer:
    def test_clean_corpus_scores_low(self, clean_dataset_zip: bytes) -> None:
        result = DatasetAnalyzer.analyze("clean.zip", clean_dataset_zip)

        assert result["status"] in {"NOT DETECTED", "SUSPICIOUS"}
        assert result["totalSamples"] == 40
        assert result["decodedSamples"] == 40
        assert result["corruptedFiles"] == 0
        assert "DS-BACKDOOR-TRIGGER-INJECTION" not in finding_ids(result)
        assert result["datasetRisk"] < 40.0

    def test_poisoned_corpus_detects_flooding_and_triggers(self, poisoned_dataset_zip: bytes) -> None:
        result = DatasetAnalyzer.analyze("poisoned.zip", poisoned_dataset_zip)

        ids = finding_ids(result)
        assert "DS-DUPLICATE-FLOODING" in ids or "DS-REDUNDANT-SAMPLES" in ids
        assert "DS-BACKDOOR-TRIGGER-INJECTION" in ids, ids
        assert result["status"] == "DETECTED"
        assert result["datasetRisk"] > 30.0

    def test_poisoning_is_attributed_to_the_right_contributor(self, poisoned_dataset_zip: bytes) -> None:
        result = DatasetAnalyzer.analyze("poisoned.zip", poisoned_dataset_zip)

        profiles = {p["name"]: p for p in result["contributorProfiles"]}
        assert "contributor_b" in profiles, profiles.keys()
        assert profiles["contributor_b"]["riskScore"] > profiles["contributor_a"]["riskScore"]

    def test_corrupt_samples_are_reported(self) -> None:
        entries = {f"train/a/img_{i}.png": png_bytes(make_image(i)) for i in range(10)}
        entries["train/a/truncated.png"] = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
        entries["train/a/not_an_image.png"] = b"this is plain text pretending to be a png"

        result = DatasetAnalyzer.analyze("mixed.zip", build_zip(entries))

        assert result["corruptedFiles"] == 2
        assert "DS-CORRUPT-SAMPLES" in finding_ids(result)

    def test_zip_slip_produces_a_critical_finding(self) -> None:
        entries = {f"train/a/img_{i}.png": png_bytes(make_image(i)) for i in range(4)}
        entries["../../../etc/cron.d/payload"] = b"* * * * * root sh -c 'id'"

        result = DatasetAnalyzer.analyze("evil.zip", build_zip(entries))

        assert "SEC-ARCHIVE-PATH-TRAVERSAL" in finding_ids(result)
        assert result["status"] == "DETECTED"

    def test_non_archive_input_fails_cleanly(self) -> None:
        result = DatasetAnalyzer.analyze("notes.txt", b"just some text, definitely not a corpus")

        assert result["status"] == "ANALYSIS FAILED"
        assert result["findings"]

    def test_result_is_deterministic(self, poisoned_dataset_zip: bytes) -> None:
        """Reproducibility is a stated requirement, so it gets a test."""
        first = DatasetAnalyzer.analyze("poisoned.zip", poisoned_dataset_zip)
        second = DatasetAnalyzer.analyze("poisoned.zip", poisoned_dataset_zip)

        assert first["datasetRisk"] == second["datasetRisk"]
        assert finding_ids(first) == finding_ids(second)
        assert first["sha256"] == second["sha256"]

    def test_coverage_matrix_declares_uncovered_threats(self, clean_dataset_zip: bytes) -> None:
        result = DatasetAnalyzer.analyze("clean.zip", clean_dataset_zip)

        coverage = {entry["threat"]: entry for entry in result["coverage"]}
        assert coverage["Clean-label poisoning"]["covered"] is False
        assert coverage["Input-aware / warping backdoors"]["covered"] is False
        assert coverage["Exact duplicate flooding"]["covered"] is True
        for entry in result["coverage"]:
            assert entry["limitation"], f"{entry['threat']} must state its limitation"


class TestNoSamplesRefusal:
    """The no-images path must refuse safely and say something useful."""

    def test_cifar_python_batches_are_recognised_and_refused(self) -> None:
        """Uploading the raw CIFAR python download is the most common real-world miss.

        The batches are pickle files; the engine must not unpickle them, must fail
        the analysis closed, and must tell the operator what it recognised. The
        payload bytes here are inert placeholders -- the point is that they are
        never parsed at all, only the entry names are examined.
        """
        payload = build_zip(
            {
                "cifar-10-batches-py/data_batch_1": b"pickled-batch-placeholder",
                "cifar-10-batches-py/data_batch_2": b"pickled-batch-placeholder",
                "cifar-10-batches-py/test_batch": b"pickled-batch-placeholder",
                "cifar-10-batches-py/batches.meta": b"pickled-batch-placeholder",
            }
        )
        result = DatasetAnalyzer.analyze("cifar-10-python.zip", payload)

        assert result["status"] == "ANALYSIS FAILED"
        assert result["datasetRisk"] == 100.0
        finding = next(f for f in result["findings"] if f["findingId"] == "DS-NO-SAMPLES")
        assert finding["evidence"]["recognisedAsCifarPythonBatches"] is True
        assert "pickle" in finding["explanation"].lower()
        assert "image layout" in finding["recommendation"] or "class folders" in finding["explanation"]

    def test_generic_non_corpus_still_refused_without_cifar_claim(self) -> None:
        payload = build_zip({"notes/readme.txt": b"hello", "misc/blob.bin": b"binary-placeholder"})
        result = DatasetAnalyzer.analyze("stuff.zip", payload)

        assert result["status"] == "ANALYSIS FAILED"
        finding = next(f for f in result["findings"] if f["findingId"] == "DS-NO-SAMPLES")
        assert finding["evidence"]["recognisedAsCifarPythonBatches"] is False
