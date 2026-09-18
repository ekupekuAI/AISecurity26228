"""Model engine tests, including a real backdoored checkpoint.

The backdoor test trains a tiny CNN on synthetic data with a poisoned subset, then
asserts that the engine detects it. That is slower than asserting on a fixture, but a
backdoor detector that has never seen a backdoor is not a tested detector.
"""

from __future__ import annotations

import io

import numpy as np
import pytest

from analyzers.model_analyzer import ModelAnalyzer
from core.models import AnalysisMode

torch = pytest.importorskip("torch")


def finding_ids(result: dict) -> set[str]:
    return {f["findingId"] for f in result["findings"]}


def _save(state: dict) -> bytes:
    buffer = io.BytesIO()
    torch.save(state, buffer)
    return buffer.getvalue()


class TinyNet(torch.nn.Module):
    """A small classifier over 3x32x32 inputs, big enough to learn a trigger."""

    def __init__(self, classes: int = 4) -> None:
        super().__init__()
        self.features = torch.nn.Sequential(
            torch.nn.Conv2d(3, 16, 3, padding=1),
            torch.nn.ReLU(),
            torch.nn.MaxPool2d(2),
            torch.nn.Conv2d(16, 32, 3, padding=1),
            torch.nn.ReLU(),
            torch.nn.AdaptiveAvgPool2d(1),
        )
        self.classifier = torch.nn.Linear(32, classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.features(x).flatten(1))


class TestSerializationSecurity:
    def test_malicious_checkpoint_is_refused_without_loading(self, malicious_pickle: bytes) -> None:
        result = ModelAnalyzer.analyze("trojan.pth", malicious_pickle)

        assert result["status"] == "DETECTED"
        assert result["analysisMode"] == AnalysisMode.REFUSED.value
        assert result["modelRisk"] == 100.0
        assert "SEC-MALICIOUS-PICKLE-OPCODE" in finding_ids(result)
        # The point of the control: nothing was deserialised.
        assert result["torchInspection"] is None

    def test_broken_stream_alone_is_refused(self, truncated_pickle: bytes) -> None:
        """No dangerous symbol present: the truncation itself must disqualify the file."""
        result = ModelAnalyzer.analyze("broken.pth", truncated_pickle)

        assert result["status"] == "DETECTED"
        assert "SEC-BROKEN-PICKLE-STREAM" in finding_ids(result)
        assert result["analysisMode"] == AnalysisMode.REFUSED.value

    def test_nullifai_shape_is_refused(self, nullifai_pickle: bytes) -> None:
        """Payload at the head, broken tail. Either finding is correct; passing is not."""
        result = ModelAnalyzer.analyze("nullifai.pth", nullifai_pickle)

        assert result["status"] == "DETECTED"
        assert finding_ids(result) & {"SEC-MALICIOUS-PICKLE-OPCODE", "SEC-BROKEN-PICKLE-STREAM"}
        assert result["modelRisk"] == 100.0

    def test_unsupported_extension_is_a_coverage_gap_not_a_pass(self) -> None:
        result = ModelAnalyzer.analyze("weights.zip", b"PK\x03\x04dummy")

        assert result["status"] == "NOT SUPPORTED"
        assert "coverage gap" in result["limitations"].lower()

    def test_safetensors_reports_no_deserialisation_risk(self) -> None:
        import json
        import struct

        header = json.dumps(
            {"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}, "__metadata__": {"format": "pt"}}
        ).encode("utf-8")
        payload = struct.pack("<Q", len(header)) + header + b"\x00" * 64

        result = ModelAnalyzer.analyze("model.safetensors", payload)

        assert result["framework"] == "safetensors"
        assert result["parameterCount"] == 16
        assert "no executable code path" in result["limitations"]


class TestStructuralAnalysis:
    def test_clean_state_dict_is_parsed(self) -> None:
        model = TinyNet()
        result = ModelAnalyzer.analyze("tiny.pth", _save(model.state_dict()))

        assert result["pickleAudit"]["verdict"] == "CLEAN"
        assert result["torchInspection"]["loadable"] is True
        assert result["parameterCount"] > 0
        assert result["weightStatistics"]["tensorCount"] > 0

    def test_nan_weights_are_flagged(self) -> None:
        state = TinyNet().state_dict()
        key = "features.0.weight"
        corrupted = state[key].clone()
        corrupted[0, 0, 0, 0] = float("nan")
        state[key] = corrupted

        result = ModelAnalyzer.analyze("broken.pth", _save(state))

        assert "MOD-NON-FINITE-WEIGHTS" in finding_ids(result)
        assert result["status"] == "DETECTED"

    def test_zeroed_layer_is_flagged_as_dead(self) -> None:
        state = TinyNet().state_dict()
        state["features.3.weight"] = torch.zeros_like(state["features.3.weight"])

        result = ModelAnalyzer.analyze("dead.pth", _save(state))

        assert "MOD-DEAD-PARAMETERS" in finding_ids(result)

    def test_whitebox_unavailable_is_stated_explicitly(self) -> None:
        """A custom architecture cannot be reconstructed, and the result must say so."""
        result = ModelAnalyzer.analyze("tiny.pth", _save(TinyNet().state_dict()))

        assert "MOD-WHITEBOX-UNAVAILABLE" in finding_ids(result)
        assert result["analysisMode"] in {AnalysisMode.GREY_BOX.value, AnalysisMode.WHITE_BOX.value}
        assert "not evidence of absence" in result["backdoorAnalysis"] or "coverage gap" in result["backdoorAnalysis"]


class TestBehaviouralDetection:
    @staticmethod
    def _train(poisoned: bool, steps: int = 220) -> torch.nn.Module:
        """Train TinyNet; when poisoned, a corner patch forces class 0."""
        torch.manual_seed(11)
        rng = np.random.default_rng(11)
        model = TinyNet(classes=4)
        optimiser = torch.optim.Adam(model.parameters(), lr=0.02)
        loss_fn = torch.nn.CrossEntropyLoss()

        # Four classes separated by colour-channel dominance: learnable in a few steps.
        def batch(n: int = 64) -> tuple[torch.Tensor, torch.Tensor]:
            labels = rng.integers(0, 4, n)
            images = rng.uniform(0.15, 0.45, (n, 3, 32, 32)).astype(np.float32)
            for i, label in enumerate(labels):
                if label < 3:
                    images[i, label] += 0.45
                else:
                    images[i] += 0.3
            images = np.clip(images, 0, 1)
            target = labels.copy()

            if poisoned:
                # Stamp 30% of the batch and relabel to class 0.
                mask = rng.random(n) < 0.3
                images[mask, :, -5:-1, -5:-1] = 1.0
                target[mask] = 0

            return torch.from_numpy(images), torch.from_numpy(target).long()

        model.train()
        for _ in range(steps):
            x, y = batch()
            optimiser.zero_grad()
            loss = loss_fn(model(x), y)
            loss.backward()
            optimiser.step()

        model.eval()
        return model

    def test_backdoored_model_shows_concentrated_flips(self) -> None:
        """A backdoor drives flips to ONE class; that concentration is the signal."""
        from modelscan.battery import run_battery

        model = self._train(poisoned=True)
        report = run_battery(model, class_count=4, channels=3, size=32, samples=96)

        assert report.ran
        if report.degenerate:
            pytest.skip("battery baseline collapsed to one class; nothing to flip away from")

        badnets = next(r for r in report.results if r.name == "checkerboard_br")
        assert badnets.flip_rate > 0.25, badnets.to_dict()
        assert badnets.concentration > 0.8, badnets.to_dict()
        assert badnets.target_class == 0, badnets.to_dict()

    def test_clean_model_is_never_reported_as_backdoored(self) -> None:
        """The negative control. A false backdoor call on a clean model is the costliest
        error this tool can make, so the assertion is on the reported conclusion, not on
        an intermediate statistic.

        A degenerate baseline is an acceptable outcome here -- it means the battery could
        not establish a baseline and the engine correctly declined to score rather than
        guessing. What is not acceptable is a positive backdoor conclusion.
        """
        from modelscan.battery import run_battery

        model = self._train(poisoned=False)
        report = run_battery(model, class_count=4, channels=3, size=32, samples=96)

        assert report.ran
        assert report.backdoor_confidence == 0.0, report.to_dict()

        if report.degenerate:
            assert report.results == []
            assert "collapsed" in report.limitation
            assert "coverage gap" in report.limitation
            return

        badnets = next(r for r in report.results if r.name == "checkerboard_br")
        assert badnets.verdict != "STRONG_BACKDOOR_INDICATION", badnets.to_dict()

    def test_neural_cleanse_produces_per_class_l1_norms(self) -> None:
        """Inversion must converge and rank classes; the MAD comparison depends on it."""
        from modelscan import neural_cleanse

        model = self._train(poisoned=True)
        report = neural_cleanse.run(model, class_count=4, channels=3, size=32, steps=60, batch_size=16)

        assert report.classes_scanned == 4
        assert len(report.inversions) == 4
        for inversion in report.inversions:
            assert inversion.l1_norm > 0
            assert 0.0 <= inversion.l1_fraction <= 1.0
            assert inversion.mask_preview
        assert report.limitation
        assert "all-to-all" in report.limitation.lower()
