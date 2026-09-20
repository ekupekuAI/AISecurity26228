"""Static pickle opcode audit for untrusted model checkpoints.

Deserialising a PyTorch `.pt`/`.pth` file is arbitrary code execution: the pickle
`REDUCE` opcode calls any callable the stream names. This module disassembles the
opcode stream with `pickletools.genops` -- which parses but never executes -- and
decides whether the checkpoint may be loaded at all.

Three design choices matter, and each is a direct response to how real scanners have
been defeated in the wild:

1. **Allowlist, not denylist.** Substring scanning for ``b"os"`` both misses obfuscated
   imports and fires on any tensor named ``conv_pos``. We enumerate every GLOBAL /
   STACK_GLOBAL target and compare it against the small set of symbols a legitimate
   torch checkpoint actually needs. Anything else is reported.

2. **Fail closed on a broken stream.** The February 2025 "nullifAI" samples on Hugging
   Face placed the payload at the *head* of a deliberately truncated pickle: the
   malicious opcodes execute, then the parse errors out, and scanners that treated a
   parse failure as "nothing to see" passed the file. A stream that cannot be fully
   disassembled is treated as hostile, and we still report every opcode decoded before
   the failure.

3. **Unwrap non-standard containers.** Those same samples were compressed with 7z
   instead of PyTorch's zip, so `torch.load` refused them and scanners never looked
   inside. We identify the container by magic bytes, transparently unwrap gzip/bzip2/xz
   and flag any container that a genuine checkpoint would never use.

References:
  - ReversingLabs, "nullifAI" malicious ML models on Hugging Face (Feb 2025)
  - PyTorch security model: `torch.load(weights_only=True)` restricted unpickler
  - MITRE ATLAS AML.T0010 (ML supply chain compromise)
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import pickletools
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterable

from core.config import SETTINGS

# --- Symbols a legitimate checkpoint is permitted to name -------------------------

#: Modules whose members are safe to reconstruct. Every entry here is something the
#: PyTorch / NumPy serialisers themselves emit.
ALLOWED_MODULES: frozenset[str] = frozenset(
    {
        "collections",
        "torch",
        "torch._utils",
        "torch.serialization",
        "torch.storage",
        "torch.nn",
        "torch.nn.modules",
        "torch.nn.modules.container",
        "torch.nn.parameter",
        "numpy",
        "numpy.core.multiarray",
        "numpy._core.multiarray",
        "numpy.core",
        "numpy._core",
        "numpy.dtype",
        "_codecs",
    }
)

#: Exact ``module.attribute`` pairs that are always safe.
ALLOWED_GLOBALS: frozenset[str] = frozenset(
    {
        "collections.OrderedDict",
        "collections.defaultdict",
        "torch._utils._rebuild_tensor",
        "torch._utils._rebuild_tensor_v2",
        "torch._utils._rebuild_tensor_v3",
        "torch._utils._rebuild_parameter",
        "torch._utils._rebuild_sparse_tensor",
        "torch._utils._rebuild_meta_tensor_no_storage",
        "torch._utils._rebuild_qtensor",
        "torch.serialization._get_layout",
        "torch.FloatStorage",
        "torch.DoubleStorage",
        "torch.HalfStorage",
        "torch.LongStorage",
        "torch.IntStorage",
        "torch.ShortStorage",
        "torch.CharStorage",
        "torch.ByteStorage",
        "torch.BoolStorage",
        "torch.BFloat16Storage",
        "torch.ComplexFloatStorage",
        "torch.ComplexDoubleStorage",
        "torch.Size",
        "torch.device",
        "torch.dtype",
        "torch.float32",
        "torch.float64",
        "torch.int64",
        "numpy.core.multiarray._reconstruct",
        "numpy._core.multiarray._reconstruct",
        "numpy.ndarray",
        "numpy.dtype",
        "_codecs.encode",
    }
)

#: Symbols that are unambiguously an execution primitive. Presence of any of these is
#: treated as an active exploit rather than an anomaly.
CRITICAL_GLOBALS: frozenset[str] = frozenset(
    {
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "os.execl",
        "os.spawnl",
        "os.spawnv",
        "os.fork",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "posix.system",
        "nt.system",
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "builtins.eval",
        "builtins.exec",
        "builtins.compile",
        "builtins.open",
        "builtins.__import__",
        "builtins.getattr",
        "builtins.setattr",
        "__builtin__.eval",
        "__builtin__.exec",
        "__builtin__.compile",
        "__builtin__.open",
        "pty.spawn",
        "runpy._run_code",
        "runpy.run_path",
        "importlib.import_module",
        "importlib._bootstrap._find_and_load",
        "shutil.rmtree",
        "socket.socket",
        "socket.create_connection",
        "ctypes.CDLL",
        "ctypes.WinDLL",
        "ctypes.cdll",
        "webbrowser.open",
        "pickle.loads",
        "codecs.decode",
        "base64.b64decode",
        "operator.attrgetter",
        "operator.methodcaller",
        "functools.reduce",
        "timeit.timeit",
        "platform.popen",
        "pdb.run",
        "bdb.Bdb.run",
        "sys.modules",
    }
)

#: Modules that should never appear anywhere in a weights file.
CRITICAL_MODULES: frozenset[str] = frozenset(
    {
        "os",
        "posix",
        "nt",
        "subprocess",
        "socket",
        "shutil",
        "pty",
        "ctypes",
        "runpy",
        "importlib",
        "webbrowser",
        "pickle",
        "marshal",
        "builtins",
        "__builtin__",
        "sys",
        "commands",
        "popen2",
        "requests",
        "urllib",
        "urllib.request",
        "http.client",
        "ftplib",
        "smtplib",
        "telnetlib",
        "paramiko",
        "pdb",
        "bdb",
        "timeit",
        "code",
        "codeop",
    }
)

#: Opcodes that can invoke a callable. Their presence is not itself proof of malice --
#: `_rebuild_tensor_v2` is invoked through REDUCE -- but they are what turns a named
#: global into execution, so we count them and pair them with the resolved target.
CALL_OPCODES: frozenset[str] = frozenset({"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"})

#: Container magic bytes. A `.pt` produced by torch is either a zip (PK\x03\x04) or a
#: raw legacy pickle; everything else here is a wrapper an attacker chose.
CONTAINER_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip-empty"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"Rar!\x1a\x07", "rar"),
    (b"ustar", "tar"),
)

PICKLE_PROTO_OPCODES = {b"\x80", b"(", b"]", b"}", b"c", b"\x28"}


@dataclass
class GlobalRef:
    """One ``GLOBAL``/``STACK_GLOBAL`` target found in a stream."""

    module: str
    name: str
    offset: int
    stream: str

    @property
    def qualname(self) -> str:
        return f"{self.module}.{self.name}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "name": self.name,
            "qualname": self.qualname,
            "offset": self.offset,
            "stream": self.stream,
        }


@dataclass
class PickleAuditResult:
    """Outcome of auditing every pickle stream inside a checkpoint."""

    verdict: str = "CLEAN"  # CLEAN | SUSPICIOUS | MALICIOUS
    container: str = "unknown"
    streams_scanned: int = 0
    opcode_count: int = 0
    globals_found: list[GlobalRef] = field(default_factory=list)
    disallowed: list[GlobalRef] = field(default_factory=list)
    critical: list[GlobalRef] = field(default_factory=list)
    call_opcodes: int = 0
    truncated_streams: list[dict[str, Any]] = field(default_factory=list)
    memo_bombs: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    protocol_versions: list[int] = field(default_factory=list)

    @property
    def safe_to_load(self) -> bool:
        """Only a fully clean audit authorises deserialisation."""
        return self.verdict == "CLEAN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "container": self.container,
            "streamsScanned": self.streams_scanned,
            "opcodeCount": self.opcode_count,
            "callOpcodes": self.call_opcodes,
            "protocolVersions": sorted(set(self.protocol_versions)),
            "globalsFound": [g.to_dict() for g in self.globals_found[:200]],
            "disallowedGlobals": [g.to_dict() for g in self.disallowed],
            "criticalGlobals": [g.to_dict() for g in self.critical],
            "truncatedStreams": self.truncated_streams,
            "memoAnomalies": self.memo_bombs,
            "notes": self.notes,
            "safeToLoad": self.safe_to_load,
        }


def identify_container(data: bytes) -> str:
    """Name the outer container by magic bytes."""
    if len(data) < 8:
        return "truncated"
    for magic, name in CONTAINER_MAGIC:
        if name == "tar":
            # `ustar` lives at offset 257, not at the head.
            if len(data) > 262 and data[257:262] == b"ustar":
                return "tar"
            continue
        if data.startswith(magic):
            return name
    # A legacy torch save begins with a pickle PROTO opcode (0x80) or an old-style
    # opcode; anything else is not a checkpoint we recognise.
    if data[:1] == b"\x80" or data[:1] in {b"(", b"c", b"]", b"}"}:
        return "raw-pickle"
    return "unknown"


def _scan_stream(data: bytes, stream_name: str, result: PickleAuditResult) -> None:
    """Disassemble one pickle stream, recording globals and any parse failure.

    `pickletools.genops` is a pure parser: it walks the opcode table and never resolves
    or calls anything. We drive it manually so that a mid-stream failure still leaves us
    with every opcode decoded up to that point -- which is exactly where a
    payload-before-truncation attack hides.
    """
    result.streams_scanned += 1
    opcodes_here = 0
    last_offset = 0
    # STACK_GLOBAL takes its module and name from the two preceding string pushes, so
    # we track the tail of the literal stack as we walk.
    recent_strings: list[str] = []

    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            opcodes_here += 1
            result.opcode_count += 1
            last_offset = pos if pos is not None else last_offset

            name = opcode.name

            if name == "PROTO" and isinstance(arg, int):
                result.protocol_versions.append(arg)

            elif name == "GLOBAL" and isinstance(arg, str):
                module, _, attr = arg.partition(" ")
                result.globals_found.append(GlobalRef(module, attr, pos or 0, stream_name))

            elif name == "STACK_GLOBAL":
                # Operands were pushed as two short strings immediately before.
                if len(recent_strings) >= 2:
                    module, attr = recent_strings[-2], recent_strings[-1]
                    result.globals_found.append(GlobalRef(module, attr, pos or 0, stream_name))
                else:
                    result.notes.append(
                        f"STACK_GLOBAL at offset {pos} in {stream_name} could not be resolved "
                        "from the literal stack; treating as opaque dynamic import."
                    )
                    result.globals_found.append(GlobalRef("<dynamic>", "<dynamic>", pos or 0, stream_name))

            elif name in CALL_OPCODES:
                result.call_opcodes += 1

            elif name in {"SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}:
                if isinstance(arg, (str, bytes)):
                    literal = arg.decode("utf-8", "replace") if isinstance(arg, bytes) else arg
                    recent_strings.append(literal)
                    if len(recent_strings) > 8:
                        recent_strings.pop(0)

            # A pickle that pushes an enormous memo is a classic memory-exhaustion
            # vector; genops itself is cheap, so we only record the anomaly.
            if opcodes_here > 5_000_000:
                result.memo_bombs.append(
                    {
                        "stream": stream_name,
                        "reason": "Opcode count exceeded 5,000,000 -- possible pickle bomb.",
                        "offset": pos,
                    }
                )
                result.notes.append(f"Aborted disassembly of {stream_name}: opcode flood.")
                break

    except Exception as exc:  # noqa: BLE001 - any parse failure is security-relevant
        # This is the nullifAI signature. Opcodes before the break already executed in a
        # real `pickle.loads`, so a truncated stream is never "clean".
        result.truncated_streams.append(
            {
                "stream": stream_name,
                "error": f"{type(exc).__name__}: {exc}",
                "opcodesDecodedBeforeFailure": opcodes_here,
                "failureOffset": last_offset,
                "bytesTotal": len(data),
                "bytesUnparsed": max(0, len(data) - last_offset),
            }
        )


def _iter_zip_pickles(data: bytes, result: PickleAuditResult) -> Iterable[tuple[str, bytes]]:
    """Yield every pickle-bearing member of a zip checkpoint, with bomb guards."""
    limits = SETTINGS.archive
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > limits.max_entries:
                result.notes.append(
                    f"Archive declares {len(infos)} entries, above the {limits.max_entries} ceiling."
                )
                infos = infos[: limits.max_entries]
            for info in infos:
                if info.is_dir():
                    continue
                name = info.filename
                if ".." in name.replace("\\", "/").split("/") or name.startswith(("/", "\\")):
                    result.notes.append(f"Zip entry escapes the archive root: {name}")
                    continue
                if info.file_size > limits.max_entry_uncompressed_bytes:
                    result.notes.append(
                        f"Skipped oversized entry {name} ({info.file_size} bytes)."
                    )
                    continue
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > limits.max_compression_ratio:
                        result.notes.append(
                            f"Entry {name} has a {ratio:.0f}:1 compression ratio -- refusing to expand."
                        )
                        continue
                total += info.file_size
                if total > limits.max_total_uncompressed_bytes:
                    result.notes.append("Aborted: total uncompressed size ceiling reached.")
                    break
                lowered = name.lower()
                # data.pkl is the state dict; constants.pkl / *.pkl carry TorchScript
                # constants. All are attacker-controlled.
                if lowered.endswith(".pkl") or lowered.endswith(".pickle") or lowered.endswith("/data"):
                    try:
                        yield name, zf.read(info)
                    except Exception as exc:  # noqa: BLE001
                        result.notes.append(f"Unreadable zip member {name}: {type(exc).__name__}")
    except zipfile.BadZipFile as exc:
        result.notes.append(f"Declared zip container is malformed: {exc}")


def _unwrap(data: bytes, container: str, result: PickleAuditResult) -> bytes:
    """Transparently decompress a single-stream wrapper, bounded by the size ceiling."""
    ceiling = SETTINGS.archive.max_entry_uncompressed_bytes
    try:
        if container == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as fh:
                return fh.read(ceiling + 1)
        if container == "bzip2":
            return bz2.BZ2Decompressor().decompress(data, ceiling + 1)
        if container == "xz":
            return lzma.LZMADecompressor().decompress(data, ceiling + 1)
    except Exception as exc:  # noqa: BLE001
        result.notes.append(f"Failed to decompress {container} wrapper: {type(exc).__name__}: {exc}")
    return b""


def _classify(result: PickleAuditResult) -> None:
    """Assign the final verdict from what the disassembly found."""
    for ref in result.globals_found:
        qual = ref.qualname
        if qual in ALLOWED_GLOBALS:
            continue
        base_module = ref.module.split(".")[0]
        # Execution primitives are fatal regardless of the namespace they hide in, so this is
        # checked first (before any allow rule below).
        if qual in CRITICAL_GLOBALS or base_module in CRITICAL_MODULES or ref.module == "<dynamic>":
            result.critical.append(ref)
            continue
        # TorchScript archives reference their own compiled types under the synthetic
        # '__torch__' namespace (e.g. __torch__.MyNet, __torch__.torch.nn.modules...), plus
        # torch.jit rebuild helpers. These are type descriptors, not importable modules or
        # execution primitives, so a legitimately scripted model must not be branded SUSPICIOUS
        # for carrying them. (An actual RCE primitive is already caught as CRITICAL above.)
        if base_module == "__torch__" or ref.module.startswith("torch.jit"):
            continue
        if ref.module in ALLOWED_MODULES and not ref.module.startswith("builtins"):
            # A torch submodule we allow but an attribute we have not enumerated.
            # Legitimate (torch adds rebuild helpers over time) but worth surfacing.
            result.disallowed.append(ref)
            continue
        result.disallowed.append(ref)

    if result.critical:
        result.verdict = "MALICIOUS"
        return

    if result.truncated_streams:
        # Payload-before-truncation. Never downgrade this.
        result.verdict = "MALICIOUS"
        result.notes.append(
            "A pickle stream failed to disassemble cleanly. Opcodes preceding the failure "
            "would already have executed under torch.load, which is the documented "
            "nullifAI evasion pattern. Treating the checkpoint as hostile."
        )
        return

    if result.container in {"7z", "rar", "lz4", "zstd", "tar", "bzip2", "xz"}:
        result.verdict = "SUSPICIOUS"
        result.notes.append(
            f"Checkpoint is wrapped in a {result.container} container. PyTorch never emits this "
            "format; non-standard wrappers are used to keep scanners and torch.load from "
            "parsing the payload."
        )
        return

    if result.disallowed or result.memo_bombs:
        result.verdict = "SUSPICIOUS"
        return

    result.verdict = "CLEAN"


def audit_checkpoint(data: bytes, filename: str = "checkpoint") -> PickleAuditResult:
    """Audit every pickle stream reachable inside `data` without executing any of it."""
    result = PickleAuditResult()
    container = identify_container(data)
    result.container = container

    if container in {"zip", "zip-empty"}:
        found_any = False
        for name, payload in _iter_zip_pickles(data, result):
            found_any = True
            _scan_stream(payload, name, result)
        if not found_any:
            result.notes.append(
                "Zip container holds no pickle stream. It may be a safetensors bundle or an "
                "archive masquerading as a checkpoint."
            )

    elif container == "raw-pickle":
        _scan_stream(data, f"{filename}:raw", result)

    elif container in {"gzip", "bzip2", "xz"}:
        inner = _unwrap(data, container, result)
        if inner:
            inner_container = identify_container(inner)
            result.notes.append(f"Unwrapped {container} wrapper; inner container is {inner_container}.")
            if inner_container in {"zip", "zip-empty"}:
                for name, payload in _iter_zip_pickles(inner, result):
                    _scan_stream(payload, f"{container}:{name}", result)
            else:
                _scan_stream(inner, f"{filename}:{container}", result)

    elif container in {"7z", "rar", "lz4", "zstd", "tar"}:
        # We deliberately do not ship a 7z/rar extractor: a defence node should not
        # grow its attack surface to read a container that no legitimate producer emits.
        result.notes.append(
            f"Container {container} is not unpacked. No trusted PyTorch or ONNX exporter "
            "produces this format for a checkpoint."
        )
        if container == "tar":
            _scan_tar(data, result)

    else:
        result.notes.append(
            "Container could not be identified from its magic bytes; the file does not match "
            "any recognised checkpoint serialisation."
        )
        # Still attempt a raw disassembly: a payload may be prefixed with junk.
        _scan_stream(data, f"{filename}:unidentified", result)

    _classify(result)
    return result


def _scan_tar(data: bytes, result: PickleAuditResult) -> None:
    """Tar members, bounded. Tar is included because legacy exporters occasionally used it."""
    limits = SETTINGS.archive
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf.getmembers()[: limits.max_entries]:
                if not member.isfile():
                    if member.issym() or member.islnk():
                        result.notes.append(f"Tar entry {member.name} is a link; refused.")
                    continue
                if member.size > limits.max_entry_uncompressed_bytes:
                    continue
                total += member.size
                if total > limits.max_total_uncompressed_bytes:
                    break
                fh: BinaryIO | None = tf.extractfile(member)
                if fh is None:
                    continue
                payload = fh.read()
                if payload[:1] == b"\x80" or member.name.endswith((".pkl", ".pickle")):
                    _scan_stream(payload, f"tar:{member.name}", result)
    except Exception as exc:  # noqa: BLE001
        result.notes.append(f"Tar inspection failed: {type(exc).__name__}: {exc}")


__all__ = [
    "ALLOWED_GLOBALS",
    "CRITICAL_GLOBALS",
    "GlobalRef",
    "PickleAuditResult",
    "audit_checkpoint",
    "identify_container",
]
