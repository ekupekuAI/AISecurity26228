"""End-to-end scoring against the labelled evaluation corpus.

These tests run the real engines over real CIFAR-10 imagery and a genuinely fine-tuned
backdoor, and assert the verdict matches the ground truth recorded in
``demo-assets/manifest.json``.

They are skipped when the corpus has not been generated, because it takes several minutes
to build. Generate it with::

    python ml-engine/scripts/make_demo_assets.py

Why this file exists: an earlier build of the model engine evaluated checkpoints at a
resolution inferred from the stem kernel rather than measured. On these very assets that
produced a CRITICAL verdict on the clean model and a clean verdict on a model with a 100%
attack success rate -- the detector was inverted, and every unit test still passed. Only a
labelled corpus catches that class of error.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from analyzers.dataset_analyzer import DatasetAnalyzer
from analyzers.model_analyzer import ModelAnalyzer

ASSETS = Path(__file__).resolve().parents[2] / "demo-assets"
MANIFEST = ASSETS / "manifest.json"

pytestmark = pytest.mark.skipif(
    not MANIFEST.is_file(),
    reason="evaluation corpus not generated; run ml-engine/scripts/make_demo_assets.py",
)


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def entry(kind: str, filename: str) -> dict:
    for item in manifest()[kind]:
        if item["file"] == filename:
            return item
    pytest.skip(f"{filename} not present in the evaluation corpus")


def finding_ids(result: dict) -> set[str]:
    return {f["findingId"] for f in result["findings"]}


def analyse_model(filename: str) -> dict:
    path = ASSETS / filename
    if not path.is_file():
        pytest.skip(f"{filename} not generated")
    return ModelAnalyzer.analyze(filename, path.read_bytes())


def analyse_dataset(filename: str) -> dict:
    path = ASSETS / filename
    if not path.is_file():
        pytest.skip(f"{filename} not generated")
    return DatasetAnalyzer.analyze(filename, path.read_bytes())


class TestModelGroundTruth:
    def test_backdoored_model_is_detected_on_the_correct_class(self) -> None:
        """The headline claim. A 100%-ASR backdoor must be found, and the target named.

        The behavioural battery is the reliable detector on synthetic imagery; Neural Cleanse
        corroborates when it can but does not lead (see the module docstring and
        MOD-NEURAL-CLEANSE-LEAD). On this fixture NC's MAD comparison is suppressed by the
        several easily-flipped classes a backdoored model carries, so the assertion is on the
        battery's verdict and the target class it names.
        """
        truth = entry("models", "backdoored_model.pth")
        assert truth["metrics"]["attackSuccessRate"] > 0.9, "the fixture itself is not backdoored"

        result = analyse_model("backdoored_model.pth")

        assert result["status"] == "DETECTED", result["limitations"]
        assert result["analysisMode"] == "WHITE_BOX"
        assert result["backdoorConfidence"] > 0.5

        expected_class = truth["groundTruth"]["targetClass"]
        battery = result["behaviouralBattery"]
        assert battery["ran"] and not battery["degenerateBaseline"]
        assert battery["suspectedTargetClass"] == expected_class, (
            f"battery suspected class {battery['suspectedTargetClass']}, expected the implanted "
            f"target class {expected_class}"
        )
        assert "MOD-BEHAVIOURAL-BACKDOOR-RESPONSE" in finding_ids(result)

    def test_backdoored_model_battery_identifies_the_trigger_family(self) -> None:
        truth = entry("models", "backdoored_model.pth")
        result = analyse_model("backdoored_model.pth")

        battery = result["behaviouralBattery"]
        assert battery["ran"] and not battery["degenerateBaseline"]
        assert battery["suspectedTargetClass"] == truth["groundTruth"]["targetClass"]

        strong = [b for b in battery["batteries"] if b["verdict"] == "STRONG_BACKDOOR_INDICATION"]
        assert strong, battery["batteries"]
        best = max(strong, key=lambda b: b["flipRate"])
        assert best["flipRate"] > 0.8
        assert best["flipConcentration"] > 0.9
        assert best["liftOverBaseline"] > 3.0

    def test_clean_model_is_not_flagged(self) -> None:
        """The negative control: a genuinely trained model with no implanted backdoor.

        The clean model must not be *detected* as backdoored. Neural Cleanse may still surface
        an uncorroborated lead on synthetic data -- a known, disclosed limitation -- but an
        uncorroborated lead is LOW severity, contributes nothing to the backdoor confidence,
        and never becomes a confirmed-backdoor finding, so it cannot condemn a clean model.
        """
        truth = entry("models", "clean_model.pth")
        assert truth["metrics"]["attackSuccessRate"] < 0.1, "the fixture is not actually clean"

        result = analyse_model("clean_model.pth")

        assert result["backdoorConfidence"] == 0.0, result["neuralCleanse"]
        assert result["behaviouralBattery"]["suspectedTargetClass"] is None
        assert "MOD-BEHAVIOURAL-BACKDOOR-RESPONSE" not in finding_ids(result)
        assert "MOD-NEURAL-CLEANSE-TRIGGER" not in finding_ids(result)

    def test_resolution_is_selected_by_measurement(self) -> None:
        """Both fixtures carry a 224-style stem but were trained at 32x32."""
        result = analyse_model("clean_model.pth")
        assert result["behaviouralBattery"]["inputShape"] == [3, 32, 32]
        assert result["behaviouralBattery"]["cleanPredictionEntropy"] > 1.0

    def test_malicious_pickle_is_refused_without_loading(self) -> None:
        result = analyse_model("malicious_model.pth")

        assert result["status"] == "DETECTED"
        assert result["analysisMode"] == "REFUSED"
        assert result["modelRisk"] == 100.0
        assert result["torchInspection"] is None

    def test_nullifai_shape_is_refused(self) -> None:
        result = analyse_model("nullifai_model.pth")

        assert result["status"] == "DETECTED"
        assert result["modelRisk"] == 100.0
        assert finding_ids(result) & {"SEC-MALICIOUS-PICKLE-OPCODE", "SEC-BROKEN-PICKLE-STREAM"}


class TestModelReliability:
    """Reproducibility: the same checkpoint must produce the same verdict every run."""

    def test_neural_cleanse_is_deterministic(self) -> None:
        from modelscan import neural_cleanse, torch_inspect

        path = ASSETS / "clean_model.pth"
        if not path.is_file():
            pytest.skip("clean_model.pth not generated")
        inspection = torch_inspect.inspect("clean_model.pth", path.read_bytes())
        if inspection.module is None:
            pytest.skip("could not reconstruct the module")

        channels = inspection.input_channels or 3
        classes = int(inspection.output_classes or 0)
        first = neural_cleanse.run(inspection.module, classes, channels, 32)
        second = neural_cleanse.run(inspection.module, classes, channels, 32)

        assert first.flagged_classes == second.flagged_classes
        assert first.backdoor_confidence == second.backdoor_confidence
        assert [round(i.l1_norm, 3) for i in first.inversions] == [round(i.l1_norm, 3) for i in second.inversions]

    def test_backdoor_verdict_is_stable_across_runs(self) -> None:
        first = analyse_model("backdoored_model.pth")
        second = analyse_model("backdoored_model.pth")

        assert first["status"] == second["status"] == "DETECTED"
        assert first["backdoorConfidence"] == second["backdoorConfidence"]
        assert first["behaviouralBattery"]["suspectedTargetClass"] == second["behaviouralBattery"]["suspectedTargetClass"]


class TestOnnxGroundTruth:
    """The same labelled checkpoints, exported to ONNX and judged through the ONNX path.

    ONNX carries no gradients, so Neural Cleanse trigger inversion cannot run; the
    behavioural battery, which needs only forward inference, can and does. These tests prove
    the ONNX path is a genuinely executed behavioural check -- it must find the backdoor and
    name the same target class as the torch path -- and that the trigger-inversion limitation
    is disclosed rather than silently skipped.
    """

    @staticmethod
    def _export_onnx(filename: str) -> bytes:
        torch = pytest.importorskip("torch")
        pytest.importorskip("onnx")
        pytest.importorskip("onnxruntime")
        import io

        from modelscan import torch_inspect

        path = ASSETS / filename
        if not path.is_file():
            pytest.skip(f"{filename} not generated")
        inspection = torch_inspect.inspect(filename, path.read_bytes())
        if inspection.module is None:
            pytest.skip("could not reconstruct the module for ONNX export")

        module = inspection.module.eval()
        buffer = io.BytesIO()
        torch.onnx.export(
            module,
            torch.zeros(1, inspection.input_channels or 3, 32, 32),
            buffer,
            input_names=["input"],
            output_names=["logits"],
            dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
            opset_version=13,
            dynamo=False,
        )
        return buffer.getvalue()

    def test_backdoored_onnx_is_detected_behaviourally(self) -> None:
        truth = entry("models", "backdoored_model.pth")
        result = ModelAnalyzer.analyze("backdoored_model.onnx", self._export_onnx("backdoored_model.pth"))

        assert result["status"] == "DETECTED", result["limitations"]
        assert result["backdoorConfidence"] > 0.5
        assert "MOD-BEHAVIOURAL-BACKDOOR-RESPONSE" in finding_ids(result)

        battery = result["behaviouralBattery"]
        assert battery["ran"] and not battery["degenerateBaseline"]
        assert battery["suspectedTargetClass"] == truth["groundTruth"]["targetClass"]

        # Trigger inversion must be declared unavailable, not silently skipped.
        assert (result.get("neuralCleanse") or {}).get("ran") in (False, None)
        assert "MOD-ONNX-TRIGGER-INVERSION-UNAVAILABLE" in finding_ids(result)

    def test_clean_onnx_is_not_flagged(self) -> None:
        result = ModelAnalyzer.analyze("clean_model.onnx", self._export_onnx("clean_model.pth"))

        assert result["backdoorConfidence"] == 0.0, result["behaviouralBattery"]
        assert "MOD-BEHAVIOURAL-BACKDOOR-RESPONSE" not in finding_ids(result)
        assert result["behaviouralBattery"]["ran"]


class TestDatasetGroundTruth:
    def test_poisoned_corpus_detects_every_planted_attack(self) -> None:
        truth = entry("datasets", "poisoned_corpus.zip")["groundTruth"]
        result = analyse_dataset("poisoned_corpus.zip")

        ids = finding_ids(result)
        assert result["status"] == "DETECTED"
        assert "DS-BACKDOOR-TRIGGER-INJECTION" in ids, ids
        assert ids & {"DS-DUPLICATE-FLOODING", "DS-REDUNDANT-SAMPLES"}, ids
        assert result["datasetRisk"] > 30.0

        # The trigger cluster should land on the class the poison targeted.
        clusters = result["triggerAnalysis"]["clusters"]
        assert clusters
        assert truth["triggerTargetClass"] in {c["label"] for c in clusters}

    def test_hostile_contributor_outranks_the_clean_one(self) -> None:
        truth = entry("datasets", "poisoned_corpus.zip")["groundTruth"]
        result = analyse_dataset("poisoned_corpus.zip")

        # Attribution uses whatever spelling the contributor manifest itself carries, so
        # the comparison is case-insensitive.
        profiles = {p["name"].lower(): p for p in result["contributorProfiles"]}
        hostile = truth["hostileContributor"].lower()
        assert hostile in profiles, list(profiles)

        others = [p for name, p in profiles.items() if name != hostile]
        assert others, "attribution collapsed every sample into one source"
        assert profiles[hostile]["riskScore"] > max(p["riskScore"] for p in others)
        assert profiles[hostile]["triggerSamples"] > 0

    def test_clean_corpus_is_not_condemned(self) -> None:
        result = analyse_dataset("clean_corpus.zip")

        assert "DS-BACKDOOR-TRIGGER-INJECTION" not in finding_ids(result)
        assert result["datasetRisk"] < 50.0, [f["findingId"] for f in result["findings"]]

    def test_coco_defects_are_enumerated(self) -> None:
        truth = entry("datasets", "coco_corpus.zip")["groundTruth"]
        result = analyse_dataset("coco_corpus.zip")

        assert result["format"] == "COCO_JSON"
        kinds = {d["kind"] for d in result["layout"]["defects"]}
        # Every planted defect kind must be recognised.
        for expected in truth["defectKinds"]:
            assert expected in kinds, f"{expected} not among {sorted(kinds)}"
