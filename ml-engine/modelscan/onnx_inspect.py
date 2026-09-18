"""ONNX graph inspection.

ONNX is the format a defence pipeline *should* be demanding from vendors, because it
carries no executable pickle. That does not make it inert: the graph is still an
instruction sequence, and a few operators can reach outside the tensor sandbox.

The inspection enumerates operators, finds structurally dead nodes, and flags operators
that do not belong in a vision inference graph. Two parsing paths are supported: the
`onnx` package when present, and a minimal protobuf field walker when it is not, so an
air-gapped node without the extra dependency still gets a real graph audit rather than a
file-size estimate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

#: Operators with no legitimate role in a vision inference graph. `If`, `Loop` and `Scan`
#: are control flow that can hide a conditional branch keyed on a trigger.
SUSPICIOUS_OPERATORS: frozenset[str] = frozenset(
    {
        "PythonOp",
        "ATen",
        "Custom",
        "If",
        "Loop",
        "Scan",
        "SequenceInsert",
        "Optional",
    }
)

#: Operators that are plainly out of place in a classification or detection network.
UNEXPECTED_OPERATORS: frozenset[str] = frozenset({"StringNormalizer", "LabelEncoder", "CategoryMapper", "TfIdfVectorizer"})


@dataclass
class OnnxInspection:
    parsed: bool = False
    parser: str = "none"
    ir_version: int | None = None
    opset: list[dict[str, Any]] = field(default_factory=list)
    producer: str | None = None
    node_count: int = 0
    operator_histogram: dict[str, int] = field(default_factory=dict)
    initializer_count: int = 0
    parameter_count: int = 0
    input_shapes: list[dict[str, Any]] = field(default_factory=list)
    output_shapes: list[dict[str, Any]] = field(default_factory=list)
    orphan_nodes: list[str] = field(default_factory=list)
    suspicious_operators: list[str] = field(default_factory=list)
    custom_domains: list[str] = field(default_factory=list)
    tensors: dict[str, np.ndarray] = field(default_factory=dict)
    structural_anomaly_score: float = 0.0
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parsed": self.parsed,
            "parser": self.parser,
            "irVersion": self.ir_version,
            "opsetImports": self.opset,
            "producer": self.producer,
            "nodeCount": self.node_count,
            "operatorHistogram": dict(sorted(self.operator_histogram.items(), key=lambda kv: -kv[1])[:40]),
            "initializerCount": self.initializer_count,
            "parameterCount": self.parameter_count,
            "inputs": self.input_shapes,
            "outputs": self.output_shapes,
            "orphanNodes": self.orphan_nodes[:20],
            "suspiciousOperators": self.suspicious_operators,
            "customDomains": self.custom_domains,
            "structuralAnomalyScore": round(self.structural_anomaly_score, 4),
            "errors": self.errors,
            "notes": self.notes,
        }


def inspect(data: bytes) -> OnnxInspection:
    result = OnnxInspection()
    try:
        import onnx  # type: ignore

        return _inspect_with_onnx(data, onnx, result)
    except ImportError:
        result.notes.append(
            "The onnx package is not installed on this node; falling back to a minimal protobuf "
            "walker. Operator enumeration is available, shape inference is not."
        )
        return _inspect_minimal(data, result)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"ONNX parse failed: {type(exc).__name__}: {exc}")
        return _inspect_minimal(data, result)


def _inspect_with_onnx(data: bytes, onnx: Any, result: OnnxInspection) -> OnnxInspection:
    model = onnx.load_from_string(data)
    result.parsed = True
    result.parser = "onnx"
    result.ir_version = int(model.ir_version)
    result.producer = f"{model.producer_name} {model.producer_version}".strip() or None
    result.opset = [{"domain": entry.domain or "ai.onnx", "version": int(entry.version)} for entry in model.opset_import]
    result.custom_domains = sorted({entry.domain for entry in model.opset_import if entry.domain and entry.domain != "ai.onnx"})

    try:
        onnx.checker.check_model(model)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"ONNX checker rejected the graph: {exc}")

    graph = model.graph
    histogram: dict[str, int] = {}
    produced: set[str] = set()
    consumed: set[str] = set()

    for node in graph.node:
        histogram[node.op_type] = histogram.get(node.op_type, 0) + 1
        produced.update(node.output)
        consumed.update(node.input)
        if node.op_type in SUSPICIOUS_OPERATORS or node.op_type in UNEXPECTED_OPERATORS:
            result.suspicious_operators.append(f"{node.op_type} ({node.name or 'unnamed'})")
        if node.domain and node.domain != "ai.onnx":
            result.suspicious_operators.append(f"{node.op_type} in custom domain '{node.domain}'")

    result.node_count = len(graph.node)
    result.operator_histogram = histogram

    graph_outputs = {output.name for output in graph.output}
    for node in graph.node:
        if node.output and not any(out in consumed or out in graph_outputs for out in node.output):
            result.orphan_nodes.append(f"{node.op_type}:{node.name or '<unnamed>'}")

    total_parameters = 0
    for initializer in graph.initializer:
        result.initializer_count += 1
        dims = [int(d) for d in initializer.dims]
        size = int(np.prod(dims)) if dims else 0
        total_parameters += size
        if len(result.tensors) < 512 and size and size < 8_000_000:
            try:
                array = onnx.numpy_helper.to_array(initializer)
                result.tensors[initializer.name] = np.asarray(array, dtype=np.float32)
            except Exception:  # noqa: BLE001
                continue
    result.parameter_count = total_parameters

    result.input_shapes = [_value_info(v) for v in graph.input]
    result.output_shapes = [_value_info(v) for v in graph.output]

    _score(result)
    return result


def _value_info(value: Any) -> dict[str, Any]:
    dims: list[Any] = []
    try:
        for dim in value.type.tensor_type.shape.dim:
            dims.append(int(dim.dim_value) if dim.dim_value else (dim.dim_param or "?"))
    except Exception:  # noqa: BLE001
        pass
    return {"name": value.name, "shape": dims}


# --- minimal protobuf fallback ---------------------------------------------------


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _iter_fields(data: bytes, start: int = 0, end: int | None = None):
    """Walk protobuf (field_number, wire_type, payload) triples without a schema."""
    pos = start
    limit = len(data) if end is None else end
    while pos < limit:
        key, pos = _read_varint(data, pos)
        field_number, wire_type = key >> 3, key & 0x7
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
            yield field_number, wire_type, value
        elif wire_type == 1:
            yield field_number, wire_type, data[pos : pos + 8]
            pos += 8
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            if pos + length > limit:
                raise ValueError("length-delimited field overruns buffer")
            yield field_number, wire_type, data[pos : pos + length]
            pos += length
        elif wire_type == 5:
            yield field_number, wire_type, data[pos : pos + 4]
            pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")


def _inspect_minimal(data: bytes, result: OnnxInspection) -> OnnxInspection:
    """Parse enough of ModelProto to enumerate operators without the onnx package.

    ModelProto: 1=ir_version, 2=producer_name, 7=graph, 8=opset_import.
    GraphProto: 1=node, 5=initializer, 11=input(ValueInfo), 12=output.
    NodeProto:  1=input, 2=output, 3=name, 4=op_type, 7=domain.
    """
    if len(data) < 8:
        result.errors.append("File is too short to be an ONNX ModelProto.")
        return result

    try:
        graph_blob: bytes | None = None
        for field_number, wire_type, value in _iter_fields(data):
            if field_number == 1 and wire_type == 0:
                result.ir_version = int(value)
            elif field_number == 2 and wire_type == 2:
                result.producer = value.decode("utf-8", "replace")
            elif field_number == 8 and wire_type == 2:
                domain, version = "ai.onnx", 0
                for sub_field, sub_wire, sub_value in _iter_fields(value):
                    if sub_field == 1 and sub_wire == 2:
                        domain = sub_value.decode("utf-8", "replace") or "ai.onnx"
                    elif sub_field == 2 and sub_wire == 0:
                        version = int(sub_value)
                result.opset.append({"domain": domain, "version": version})
                if domain not in {"ai.onnx", ""}:
                    result.custom_domains.append(domain)
            elif field_number == 7 and wire_type == 2:
                graph_blob = value

        if graph_blob is None:
            result.errors.append("No GraphProto field found; the file is not an ONNX model.")
            return result

        histogram: dict[str, int] = {}
        consumed: set[str] = set()
        produced: list[tuple[str, list[str]]] = []
        outputs: set[str] = set()

        for field_number, wire_type, value in _iter_fields(graph_blob):
            if field_number == 1 and wire_type == 2:  # NodeProto
                op_type, name, domain = "", "", ""
                node_inputs: list[str] = []
                node_outputs: list[str] = []
                for sub_field, sub_wire, sub_value in _iter_fields(value):
                    if sub_wire != 2:
                        continue
                    text = sub_value.decode("utf-8", "replace")
                    if sub_field == 1:
                        node_inputs.append(text)
                    elif sub_field == 2:
                        node_outputs.append(text)
                    elif sub_field == 3:
                        name = text
                    elif sub_field == 4:
                        op_type = text
                    elif sub_field == 7:
                        domain = text
                if op_type:
                    histogram[op_type] = histogram.get(op_type, 0) + 1
                    result.node_count += 1
                    consumed.update(node_inputs)
                    produced.append((f"{op_type}:{name or '<unnamed>'}", node_outputs))
                    if op_type in SUSPICIOUS_OPERATORS or op_type in UNEXPECTED_OPERATORS:
                        result.suspicious_operators.append(f"{op_type} ({name or 'unnamed'})")
                    if domain and domain != "ai.onnx":
                        result.suspicious_operators.append(f"{op_type} in custom domain '{domain}'")
                        result.custom_domains.append(domain)
            elif field_number == 5 and wire_type == 2:  # TensorProto initializer
                result.initializer_count += 1
                dims: list[int] = []
                for sub_field, sub_wire, sub_value in _iter_fields(value):
                    if sub_field == 1 and sub_wire == 0:
                        dims.append(int(sub_value))
                if dims:
                    result.parameter_count += int(np.prod(dims))
            elif field_number == 12 and wire_type == 2:  # graph output ValueInfo
                for sub_field, sub_wire, sub_value in _iter_fields(value):
                    if sub_field == 1 and sub_wire == 2:
                        outputs.add(sub_value.decode("utf-8", "replace"))

        for label, node_outputs in produced:
            if node_outputs and not any(out in consumed or out in outputs for out in node_outputs):
                result.orphan_nodes.append(label)

        result.parsed = result.node_count > 0
        result.parser = "minimal-protobuf"
        result.operator_histogram = histogram
        result.custom_domains = sorted(set(result.custom_domains))
        if not result.parsed:
            result.errors.append("Protobuf parsed but contained no nodes; the graph is empty or malformed.")

    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"Minimal protobuf walk failed: {type(exc).__name__}: {exc}")
        return result

    _score(result)
    return result


def _score(result: OnnxInspection) -> None:
    score = 0.0
    if result.suspicious_operators:
        score += min(0.5, 0.15 * len(result.suspicious_operators))
    if result.orphan_nodes:
        score += min(0.3, 0.05 * len(result.orphan_nodes))
    if result.custom_domains:
        score += 0.2
    if result.errors:
        score += 0.2
    result.structural_anomaly_score = min(1.0, score)


__all__ = ["OnnxInspection", "SUSPICIOUS_OPERATORS", "inspect"]
