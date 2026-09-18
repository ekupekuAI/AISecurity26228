"""Multipart parsing tests.

The parser sits directly on untrusted input and its output decides which analysis path a
file takes. A filename that parses wrongly can route a hostile checkpoint to the
"unsupported format" branch, which silently disables the serialisation control -- that is
exactly what happened with an earlier version that split the whole header block on ';'
and let the filename absorb the following `Content-Type` header.
"""

from __future__ import annotations

import pytest

from app import _extract_multipart

BOUNDARY = "----aiaTESTBOUNDARY"
CONTENT_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def build(filename: str, payload: bytes = b"DATA", include_content_type: bool = True) -> bytes:
    lines = [
        f"--{BOUNDARY}",
        f'Content-Disposition: form-data; name="file"; filename="{filename}"',
    ]
    if include_content_type:
        lines.append("Content-Type: application/octet-stream")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + payload + f"\r\n--{BOUNDARY}--\r\n".encode("latin-1")


class TestFilenameParsing:
    def test_filename_stops_at_end_of_its_own_header_line(self) -> None:
        """The regression. A following Content-Type header must not be absorbed."""
        name, content = _extract_multipart(build("malicious_model.pth"), CONTENT_TYPE)

        assert name == "malicious_model.pth"
        assert content == b"DATA"

    def test_filename_without_a_following_header(self) -> None:
        name, content = _extract_multipart(
            build("corpus.zip", include_content_type=False), CONTENT_TYPE
        )
        assert name == "corpus.zip"
        assert content == b"DATA"

    @pytest.mark.parametrize(
        ("supplied", "expected"),
        [
            ("../../etc/passwd", "passwd"),
            ("C:\\Windows\\System32\\evil.pth", "evil.pth"),
            ("dir/sub/model.onnx", "model.onnx"),
            ("model.pth", "model.pth"),
        ],
    )
    def test_paths_are_reduced_to_a_basename(self, supplied: str, expected: str) -> None:
        name, _ = _extract_multipart(build(supplied), CONTENT_TYPE)
        assert name == expected

    def test_unsafe_characters_are_stripped(self) -> None:
        name, _ = _extract_multipart(build('we|ird?<>.pth'), CONTENT_TYPE)
        assert name == "weird.pth"

    def test_empty_filename_falls_back(self) -> None:
        name, content = _extract_multipart(build(""), CONTENT_TYPE)
        assert name == "upload.bin"
        assert content == b"DATA"

    def test_binary_payload_survives_intact(self) -> None:
        payload = bytes(range(256)) * 4
        name, content = _extract_multipart(build("blob.pt", payload), CONTENT_TYPE)
        assert name == "blob.pt"
        assert content == payload

    def test_payload_containing_crlf_survives(self) -> None:
        payload = b"line1\r\nline2\r\n\r\nline3"
        _, content = _extract_multipart(build("x.pt", payload), CONTENT_TYPE)
        assert content == payload


class TestMalformedBodies:
    def test_missing_boundary_is_refused(self) -> None:
        name, content = _extract_multipart(build("x.pt"), "multipart/form-data")
        assert content is None

    def test_non_multipart_body_is_passed_through(self) -> None:
        name, content = _extract_multipart(b"raw bytes", "application/octet-stream")
        assert content == b"raw bytes"

    def test_part_without_a_filename_is_skipped(self) -> None:
        body = (
            f"--{BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="note"\r\n\r\n'
            "just a field\r\n"
            f"--{BOUNDARY}--\r\n"
        ).encode("latin-1")

        _, content = _extract_multipart(body, CONTENT_TYPE)
        assert content is None

    def test_field_before_file_does_not_shadow_it(self) -> None:
        body = (
            f"--{BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="note"\r\n\r\n'
            "metadata\r\n"
            f"--{BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="file"; filename="real.pth"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
            "PAYLOAD\r\n"
            f"--{BOUNDARY}--\r\n"
        ).encode("latin-1")

        name, content = _extract_multipart(body, CONTENT_TYPE)
        assert name == "real.pth"
        assert content == b"PAYLOAD"
