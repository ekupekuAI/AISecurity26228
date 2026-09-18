"""PyTorch checkpoint structural inspection and safe white-box recovery.

Loading a checkpoint is the only way to run a behavioural battery or Neural Cleanse, and
loading a checkpoint is also arbitrary code execution. The order of operations here is
the whole point:

  1. Audit every pickle opcode statically (`security.pickle_audit`).
  2. Refuse outright if the audit is anything other than CLEAN.
  3. Only then call `torch.load(..., weights_only=True)`, which uses PyTorch's own
     restricted unpickler as a second independent control.

Two independent controls in series, and the expensive one never runs on a file the cheap
one rejected.

Recovering a *callable* model from a bare state dict is a separate problem: a state dict
is parameters without topology. We match the tensor shape signature against a registry
of standard vision architectures and only claim white-box access when a candidate loads
with `strict=True`. Anything less is reported as grey-box, because a model we cannot run
is a model we cannot make behavioural claims about.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from core.config import SETTINGS
from security.pickle_audit import PickleAuditResult, audit_checkpoint

#: Layer-name fragments that identify an architecture family from a state dict alone.
ARCHITECTURE_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PreAct-ResNet", re.compile(r"(?:^|\.)(?:layer\d\.\d\.bn1\.weight)", re.IGNORECASE)),
    ("ResNet", re.compile(r"(?:^|\.)layer\d\.\d\.conv\d\.weight", re.IGNORECASE)),
    ("VGG", re.compile(r"^features\.\d+\.weight", re.IGNORECASE)),
    ("DenseNet", re.compile(r"denseblock\d+\.denselayer", re.IGNORECASE)),
    ("Vision Transformer", re.compile(r"(?:blocks?\.\d+\.attn|encoder\.layers?\.\d+\.self_attn)", re.IGNORECASE)),
    ("ConvNeXt", re.compile(r"stages?\.\d+\.blocks?\.\d+\.dwconv", re.IGNORECASE)),
    ("YOLO", re.compile(r"(?:^|\.)model\.\d+\.(?:cv\d|m\.\d)", re.IGNORECASE)),
    ("EfficientNet", re.compile(r"_blocks\.\d+\._expand_conv", re.IGNORECASE)),
    ("MobileNet", re.compile(r"features\.\d+\.conv\.\d+\.\d+\.weight", re.IGNORECASE)),
)


@dataclass
class TorchInspection:
    framework: str = "PyTorch"
    container: str = "unknown"
    architecture: str = "Unknown"
    architecture_confidence: float = 0.0
    parameter_count: int = 0
    tensor_count: int = 0
    layer_names: list[str] = field(default_factory=list)
    output_classes: int | None = None
    input_channels: int | None = None
    loadable: bool = False
    executable: bool = False
    torchscript: bool = False
    audit: PickleAuditResult | None = None
    tensors: dict[str, np.ndarray] = field(default_factory=dict)
    module: Any = None
    zip_entries: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "container": self.container,
            "architecture": self.architecture,
            "architectureConfidence": round(self.architecture_confidence, 3),
            "parameterCount": self.parameter_count,
            "tensorCount": self.tensor_count,
            "outputClasses": self.output_classes,
            "inputChannels": self.input_channels,
            "loadable": self.loadable,
            "executable": self.executable,
            "torchScript": self.torchscript,
            "layerSample": self.layer_names[:40],
            "zipEntries": self.zip_entries[:30],
            "errors": self.errors,
            "notes": self.notes,
        }


def inspect(filename: str, data: bytes) -> TorchInspection:
    """Full static inspection, escalating to white-box only when it is safe to."""
    result = TorchInspection()
    audit = audit_checkpoint(data, filename)
    result.audit = audit
    result.container = audit.container

    if audit.container in {"zip", "zip-empty"}:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                result.zip_entries = zf.namelist()[:400]
                result.torchscript = any(name.startswith(("code/", "constants.pkl")) or "/code/" in name for name in result.zip_entries)
        except zipfile.BadZipFile as exc:
            result.errors.append(f"Zip container unreadable: {exc}")

    if not audit.safe_to_load:
        result.notes.append(
            f"Static opcode audit returned {audit.verdict}; the checkpoint was not deserialised. "
            "No behavioural claim can be made about it."
        )
        return result

    if not SETTINGS.allow_model_execution:
        result.notes.append("Model execution is disabled by configuration; inspection stopped at the container level.")
        return result

    try:
        import torch
    except Exception as exc:  # noqa: BLE001
        result.errors.append(f"PyTorch unavailable: {type(exc).__name__}: {exc}")
        return result

    torch.set_num_threads(max(1, SETTINGS.torch_threads))

    # TorchScript first: it carries its own topology, so it is the best case.
    if result.torchscript:
        try:
            module = torch.jit.load(io.BytesIO(data), map_location="cpu")
            module.eval()
            result.module = module
            result.loadable = True
            result.executable = True
            result.architecture = "TorchScript module (self-describing graph)"
            result.architecture_confidence = 1.0
            state = dict(module.state_dict())
            result.tensors = {k: v.detach().cpu().numpy() for k, v in state.items() if hasattr(v, "detach")}
            result.layer_names = list(result.tensors)
            result.parameter_count = int(sum(v.size for v in result.tensors.values()))
            result.tensor_count = len(result.tensors)
            _infer_io_shape(result)
            return result
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"TorchScript load failed, falling back to state-dict parsing: {type(exc).__name__}")

    # weights_only=True is PyTorch's restricted unpickler: it refuses any global outside
    # its own allowlist. This is our second independent control.
    try:
        loaded = torch.load(io.BytesIO(data), map_location="cpu", weights_only=True)
    except Exception as exc:  # noqa: BLE001
        result.errors.append(
            f"Restricted torch.load(weights_only=True) refused the checkpoint: {type(exc).__name__}: {exc}"
        )
        result.notes.append(
            "PyTorch's own restricted unpickler rejected this file even though the opcode audit "
            "passed. The checkpoint is malformed or uses a non-standard serialisation."
        )
        return result

    state = _extract_state_dict(loaded, result)
    if state is None:
        return result

    result.loadable = True
    tensors: dict[str, np.ndarray] = {}
    for key, value in state.items():
        if hasattr(value, "detach") and hasattr(value, "cpu"):
            try:
                tensors[str(key)] = value.detach().cpu().float().numpy()
            except Exception:  # noqa: BLE001
                continue
        elif isinstance(value, np.ndarray):
            tensors[str(key)] = value

    result.tensors = tensors
    result.layer_names = list(tensors)
    result.tensor_count = len(tensors)
    result.parameter_count = int(sum(v.size for v in tensors.values()))
    _identify_architecture(result)
    _infer_io_shape(result)
    _try_reconstruct(result, torch)
    return result


def _extract_state_dict(loaded: Any, result: TorchInspection) -> dict[str, Any] | None:
    """Unwrap the common checkpoint envelopes to reach the parameter mapping."""
    if isinstance(loaded, dict):
        for key in ("state_dict", "model_state_dict", "model", "net", "weights"):
            inner = loaded.get(key)
            if isinstance(inner, dict) and inner:
                result.notes.append(f"State dict recovered from checkpoint key '{key}'.")
                # Strip DistributedDataParallel's "module." prefix.
                if all(str(k).startswith("module.") for k in inner):
                    return {str(k)[7:]: v for k, v in inner.items()}
                return {str(k): v for k, v in inner.items()}
        if loaded and all(hasattr(v, "detach") or isinstance(v, np.ndarray) for v in loaded.values()):
            if all(str(k).startswith("module.") for k in loaded):
                return {str(k)[7:]: v for k, v in loaded.items()}
            return {str(k): v for k, v in loaded.items()}
        result.errors.append(
            "Checkpoint is a dictionary but contains no recognisable parameter mapping. "
            f"Top-level keys: {list(loaded)[:12]}"
        )
        return None

    result.errors.append(f"Checkpoint deserialised to {type(loaded).__name__}, not a state dict.")
    return None


def _identify_architecture(result: TorchInspection) -> None:
    joined = "\n".join(result.layer_names)
    for name, pattern in ARCHITECTURE_SIGNATURES:
        if pattern.search(joined):
            result.architecture = f"{name} (inferred from parameter naming)"
            result.architecture_confidence = 0.8
            return

    if any("conv" in n.lower() for n in result.layer_names):
        result.architecture = "Convolutional network (family not identified)"
        result.architecture_confidence = 0.4
    elif any("attn" in n.lower() or "attention" in n.lower() for n in result.layer_names):
        result.architecture = "Attention-based network (family not identified)"
        result.architecture_confidence = 0.4
    else:
        result.architecture = "Unrecognised topology"
        result.architecture_confidence = 0.1


def _infer_io_shape(result: TorchInspection) -> None:
    """Recover class count and input channels from the first and last weight tensors."""
    # Output classes: the trailing 2-D weight's first dimension, or a trailing bias.
    for name in reversed(result.layer_names):
        tensor = result.tensors.get(name)
        if tensor is None:
            continue
        if tensor.ndim == 2 and ("fc" in name.lower() or "classifier" in name.lower() or "head" in name.lower()):
            result.output_classes = int(tensor.shape[0])
            break
    if result.output_classes is None:
        for name in reversed(result.layer_names):
            tensor = result.tensors.get(name)
            if tensor is not None and tensor.ndim == 2 and tensor.shape[0] <= 10000:
                result.output_classes = int(tensor.shape[0])
                break

    for name in result.layer_names:
        tensor = result.tensors.get(name)
        if tensor is not None and tensor.ndim == 4:
            result.input_channels = int(tensor.shape[1])
            break


def _try_reconstruct(result: TorchInspection, torch: Any) -> None:
    """Attempt to instantiate a matching torchvision architecture and load strictly.

    Only `strict=True` counts. A partial load produces a model whose behaviour is not the
    submitted model's behaviour, and running a backdoor battery against that would be
    worse than running none at all.
    """
    if not result.tensors or result.output_classes is None:
        return

    try:
        from torchvision.models import resnet18, resnet34, resnet50, vgg16
    except Exception as exc:  # noqa: BLE001
        result.notes.append(f"torchvision unavailable for architecture reconstruction: {type(exc).__name__}")
        return

    num_classes = int(result.output_classes)
    candidates = []
    lowered = result.architecture.lower()
    if "resnet" in lowered:
        candidates = [("resnet18", resnet18), ("resnet34", resnet34), ("resnet50", resnet50)]
    elif "vgg" in lowered:
        candidates = [("vgg16", vgg16)]
    else:
        candidates = [("resnet18", resnet18), ("resnet34", resnet34)]

    state = {k: torch.from_numpy(np.ascontiguousarray(v)) for k, v in result.tensors.items()}

    for name, factory in candidates:
        try:
            model = factory(weights=None, num_classes=num_classes)
        except Exception:  # noqa: BLE001
            continue

        try:
            model.load_state_dict(state, strict=True)
        except Exception:
            # CIFAR-style ResNets replace the 7x7 stem and drop maxpool. Retrofit and retry,
            # because that variant is overwhelmingly common in backdoor research corpora.
            try:
                stem = result.tensors.get("conv1.weight")
                if stem is not None and stem.ndim == 4 and stem.shape[-1] == 3:
                    model.conv1 = torch.nn.Conv2d(
                        int(stem.shape[1]), int(stem.shape[0]), kernel_size=3, stride=1, padding=1, bias=False
                    )
                    model.maxpool = torch.nn.Identity()
                    model.load_state_dict(state, strict=True)
                else:
                    continue
            except Exception:  # noqa: BLE001
                continue

        model.eval()
        for param in model.parameters():
            param.requires_grad_(False)
        result.module = model
        result.executable = True
        result.architecture = f"{name} ({num_classes} classes, reconstructed and strictly loaded)"
        result.architecture_confidence = 0.95
        result.notes.append(
            f"White-box access obtained: parameters load into a {name} skeleton with strict=True, "
            "so the executed graph is the submitted model."
        )
        return

    result.notes.append(
        "No standard architecture accepted this state dict under strict loading. Assessment "
        "remains grey-box: parameter statistics are available, behavioural tests are not. "
        "Supplying the checkpoint as TorchScript or ONNX would enable full white-box analysis."
    )


__all__ = ["TorchInspection", "inspect"]
