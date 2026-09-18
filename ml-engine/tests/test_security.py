"""Security-control tests: pickle auditing and archive hardening.

These are the controls that stand between an untrusted vendor upload and code execution
on the node, so they get adversarial tests rather than happy-path ones.
"""

from __future__ import annotations

import io
import zipfile

import pytest

from security.archive import ArchiveReport, is_unsafe_path, iter_archive
from security.pickle_audit import audit_checkpoint, identify_container


class TestPickleAudit:
    def test_clean_state_dict_passes(self) -> None:
        torch = pytest.importorskip("torch")
        buffer = io.BytesIO()
        torch.save({"layer.weight": torch.zeros(4, 4), "layer.bias": torch.zeros(4)}, buffer)

        result = audit_checkpoint(buffer.getvalue(), "clean.pt")

        assert result.verdict == "CLEAN", result.to_dict()
        assert result.safe_to_load
        assert result.critical == []
        assert result.opcode_count > 0

    def test_os_system_is_critical(self, malicious_pickle: bytes) -> None:
        result = audit_checkpoint(malicious_pickle, "trojan.pt")

        assert result.verdict == "MALICIOUS"
        assert not result.safe_to_load
        assert any(ref.qualname == "os.system" for ref in result.critical)

    def test_truncated_stream_fails_closed(self, truncated_pickle: bytes) -> None:
        """The nullifAI pattern: a payload that executes before the parser gives up.

        A scanner that treats a parse error as 'nothing found' passes this file. We must
        not.
        """
        result = audit_checkpoint(truncated_pickle, "broken.pt")

        assert result.verdict == "MALICIOUS"
        assert result.truncated_streams, "a failed disassembly must be recorded"
        assert result.truncated_streams[0]["opcodesDecodedBeforeFailure"] > 0

    def test_non_standard_container_is_suspicious(self) -> None:
        """7z-wrapped checkpoints were the nullifAI delivery mechanism."""
        seven_zip = b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64

        result = audit_checkpoint(seven_zip, "model.pt")

        assert identify_container(seven_zip) == "7z"
        assert result.verdict == "SUSPICIOUS"
        assert not result.safe_to_load
        assert any("7z" in note for note in result.notes)

    def test_gzip_wrapper_is_unwrapped_and_scanned(self) -> None:
        import gzip

        inner = b"\x80\x04cos\nsystem\nX\x02\x00\x00\x00shq\x00\x85R."
        wrapped = gzip.compress(inner)

        result = audit_checkpoint(wrapped, "model.pt")

        assert result.verdict == "MALICIOUS"
        assert any(ref.qualname == "os.system" for ref in result.critical)

    def test_substring_false_positive_is_not_raised(self) -> None:
        """A tensor named 'conv_pos' must not trip an 'os' substring match."""
        torch = pytest.importorskip("torch")
        buffer = io.BytesIO()
        torch.save({"backbone.conv_pos.weight": torch.zeros(2, 2), "head.exec_gate": torch.zeros(2)}, buffer)

        result = audit_checkpoint(buffer.getvalue(), "benign.pt")

        assert result.verdict == "CLEAN", result.to_dict()

    def test_subprocess_import_is_critical(self) -> None:
        payload = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00csubprocess\nPopen\n)R."

        result = audit_checkpoint(payload, "rev.pt")

        assert result.verdict == "MALICIOUS"


class TestArchiveGuards:
    @pytest.mark.parametrize(
        "path",
        [
            "../../../etc/shadow",
            "/etc/passwd",
            "C:\\Windows\\System32\\config",
            "\\\\server\\share\\file",
            "a/../../b.png",
            "x\x00.png",
        ],
    )
    def test_unsafe_paths_rejected(self, path: str) -> None:
        assert is_unsafe_path(path) is not None

    @pytest.mark.parametrize("path", ["train/cat/001.png", "a/b/c/d.jpg", "root.png"])
    def test_safe_paths_accepted(self, path: str) -> None:
        assert is_unsafe_path(path) is None

    def test_zip_slip_entry_is_reported_not_yielded(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr("../../escape.png", b"x" * 16)
            zf.writestr("safe/ok.png", b"y" * 16)

        report = ArchiveReport()
        names = [entry.name for entry in iter_archive(buffer.getvalue(), report)]

        assert names == ["safe/ok.png"]
        assert report.has_traversal_attempt
        assert any(v.kind == "path-traversal" for v in report.violations)

    def test_compression_bomb_is_refused(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            # 8 MB of zeros compresses to a few KB: ratio far past the ceiling.
            zf.writestr("bomb.bin", b"\x00" * (8 * 1024 * 1024))
            zf.writestr("real.png", b"z" * 4096)

        report = ArchiveReport()
        names = [entry.name for entry in iter_archive(buffer.getvalue(), report)]

        assert "bomb.bin" not in names
        assert any(v.kind == "compression-bomb" for v in report.violations)

    def test_malformed_archive_aborts_cleanly(self) -> None:
        report = ArchiveReport()
        entries = list(iter_archive(b"this is not an archive at all", report))

        assert entries == []
        assert report.aborted
        assert report.abort_reason
