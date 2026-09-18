"""Bounded, in-memory archive traversal for untrusted dataset submissions.

A contributor archive is hostile input. Three classes of attack are handled here:

* **Decompression bombs** -- an entry that expands 1000:1, or a corpus whose total
  expansion exceeds the node's memory. Every read is checked against a per-entry
  ceiling, a running total, an entry count and a compression ratio.
* **Path traversal (Zip Slip)** -- entry names containing ``..``, absolute paths,
  Windows drive letters or UNC prefixes. Nothing is ever written to disk from an
  archive, but a traversal attempt is itself reportable evidence of a crafted archive.
* **Symlink and device entries** -- a tar member pointing at ``/etc/shadow`` turns a
  later read into an arbitrary file read.

The traversal never materialises the whole archive: callers stream entries and decide
what to keep.
"""

from __future__ import annotations

import io
import posixpath
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, Iterator

from core.config import SETTINGS

#: Windows drive-letter or UNC prefixes, which `posixpath` will not catch.
_ABSOLUTE_PATTERNS = (
    re.compile(r"^[a-zA-Z]:[\\/]"),
    re.compile(r"^\\\\"),
    re.compile(r"^/"),
)


@dataclass
class ArchiveViolation:
    kind: str
    entry: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "entry": self.entry, "detail": self.detail}


@dataclass
class ArchiveEntry:
    name: str
    data: bytes
    size: int
    compressed_size: int


@dataclass
class ArchiveReport:
    """What the traversal saw, including everything it refused."""

    format: str = "unknown"
    entries_seen: int = 0
    entries_yielded: int = 0
    total_uncompressed: int = 0
    violations: list[ArchiveViolation] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "entriesSeen": self.entries_seen,
            "entriesYielded": self.entries_yielded,
            "totalUncompressedBytes": self.total_uncompressed,
            "violations": [v.to_dict() for v in self.violations[:100]],
            "violationCount": len(self.violations),
            "aborted": self.aborted,
            "abortReason": self.abort_reason,
        }

    @property
    def has_traversal_attempt(self) -> bool:
        return any(v.kind in {"path-traversal", "absolute-path", "link-entry"} for v in self.violations)


def is_unsafe_path(name: str) -> str | None:
    """Return a reason string when an archive entry name must be refused."""
    if not name or name.strip() in {"", ".", ".."}:
        return "empty or dot-only entry name"

    normalised = name.replace("\\", "/")

    for pattern in _ABSOLUTE_PATTERNS:
        if pattern.match(normalised):
            return "absolute path"

    if "\x00" in name:
        return "null byte in entry name"

    parts = normalised.split("/")
    if ".." in parts:
        return "parent-directory traversal component"

    if len(parts) > SETTINGS.archive.max_path_depth:
        return f"path depth {len(parts)} exceeds ceiling {SETTINGS.archive.max_path_depth}"

    if len(name) > SETTINGS.archive.max_path_length:
        return f"path length {len(name)} exceeds ceiling {SETTINGS.archive.max_path_length}"

    # Defence in depth: after normalisation the path must still be relative and inside.
    resolved = posixpath.normpath(posixpath.join("/root", normalised))
    if not resolved.startswith("/root/"):
        return "entry escapes the archive root after normalisation"

    return None


def detect_format(data: bytes) -> str:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:2] == b"\x1f\x8b":
        return "tar.gz"
    if data[:3] == b"BZh":
        return "tar.bz2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "tar.xz"
    return "raw"


def iter_archive(data: bytes, report: ArchiveReport) -> Iterator[ArchiveEntry]:
    """Yield archive members, enforcing every bomb and traversal guard."""
    fmt = detect_format(data)
    report.format = fmt
    if fmt == "zip":
        yield from _iter_zip(data, report)
    elif fmt.startswith("tar"):
        yield from _iter_tar(data, report)
    else:
        report.aborted = True
        report.abort_reason = "Payload is not a recognised archive container."


def _iter_zip(data: bytes, report: ArchiveReport) -> Iterator[ArchiveEntry]:
    limits = SETTINGS.archive
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        report.aborted = True
        report.abort_reason = f"Archive is not a readable zip: {exc}"
        return

    with zf:
        infos = zf.infolist()
        if len(infos) > limits.max_entries:
            report.violations.append(
                ArchiveViolation(
                    "entry-flood",
                    "<archive>",
                    f"{len(infos)} entries exceeds the {limits.max_entries} ceiling; truncating.",
                )
            )
            infos = infos[: limits.max_entries]

        for info in infos:
            report.entries_seen += 1
            name = info.filename

            if info.is_dir():
                continue

            # Mode bits above 0o120000 mark a symlink in a zip produced on POSIX.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                report.violations.append(
                    ArchiveViolation("link-entry", name, "Zip entry is a symbolic link; refused.")
                )
                continue

            reason = is_unsafe_path(name)
            if reason is not None:
                kind = "absolute-path" if "absolute" in reason else "path-traversal"
                report.violations.append(ArchiveViolation(kind, name, reason))
                continue

            if info.file_size > limits.max_entry_uncompressed_bytes:
                report.violations.append(
                    ArchiveViolation(
                        "oversized-entry",
                        name,
                        f"declared {info.file_size} bytes, above the per-entry ceiling",
                    )
                )
                continue

            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > limits.max_compression_ratio:
                    report.violations.append(
                        ArchiveViolation(
                            "compression-bomb",
                            name,
                            f"expansion ratio {ratio:.1f}:1 exceeds {limits.max_compression_ratio:.0f}:1",
                        )
                    )
                    continue

            if report.total_uncompressed + info.file_size > limits.max_total_uncompressed_bytes:
                report.aborted = True
                report.abort_reason = (
                    "Cumulative uncompressed size ceiling reached; the archive expands beyond "
                    "what this node will hold in memory."
                )
                return

            try:
                payload = zf.read(info)
            except Exception as exc:  # noqa: BLE001
                report.violations.append(
                    ArchiveViolation("unreadable-entry", name, f"{type(exc).__name__}: {exc}")
                )
                continue

            # A zip header can lie about file_size; the real read is authoritative.
            if len(payload) > limits.max_entry_uncompressed_bytes:
                report.violations.append(
                    ArchiveViolation(
                        "header-mismatch",
                        name,
                        f"header declared {info.file_size} bytes but {len(payload)} were produced",
                    )
                )
                continue

            report.total_uncompressed += len(payload)
            report.entries_yielded += 1
            yield ArchiveEntry(name=name, data=payload, size=len(payload), compressed_size=info.compress_size)


def _iter_tar(data: bytes, report: ArchiveReport) -> Iterator[ArchiveEntry]:
    limits = SETTINGS.archive
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except Exception as exc:  # noqa: BLE001
        report.aborted = True
        report.abort_reason = f"Archive is not a readable tar: {type(exc).__name__}: {exc}"
        return

    with tf:
        count = 0
        for member in tf:
            count += 1
            if count > limits.max_entries:
                report.violations.append(
                    ArchiveViolation("entry-flood", "<archive>", "entry ceiling reached; truncating.")
                )
                break
            report.entries_seen += 1
            name = member.name

            if member.issym() or member.islnk():
                report.violations.append(
                    ArchiveViolation("link-entry", name, f"tar entry links to {member.linkname}; refused")
                )
                continue
            if member.isdev() or member.isfifo():
                report.violations.append(
                    ArchiveViolation("device-entry", name, "tar entry is a device or FIFO; refused")
                )
                continue
            if not member.isfile():
                continue

            reason = is_unsafe_path(name)
            if reason is not None:
                kind = "absolute-path" if "absolute" in reason else "path-traversal"
                report.violations.append(ArchiveViolation(kind, name, reason))
                continue

            if member.size > limits.max_entry_uncompressed_bytes:
                report.violations.append(
                    ArchiveViolation("oversized-entry", name, f"declared {member.size} bytes")
                )
                continue

            if report.total_uncompressed + member.size > limits.max_total_uncompressed_bytes:
                report.aborted = True
                report.abort_reason = "Cumulative uncompressed size ceiling reached."
                return

            fh = tf.extractfile(member)
            if fh is None:
                continue
            payload = fh.read(limits.max_entry_uncompressed_bytes + 1)
            if len(payload) > limits.max_entry_uncompressed_bytes:
                report.violations.append(
                    ArchiveViolation("oversized-entry", name, "stream exceeded per-entry ceiling on read")
                )
                continue

            report.total_uncompressed += len(payload)
            report.entries_yielded += 1
            yield ArchiveEntry(name=name, data=payload, size=len(payload), compressed_size=member.size)


__all__ = [
    "ArchiveEntry",
    "ArchiveReport",
    "ArchiveViolation",
    "detect_format",
    "is_unsafe_path",
    "iter_archive",
]
