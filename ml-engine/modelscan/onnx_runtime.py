"""Forward-only execution of an ONNX graph for behavioural testing.

ONNX carries no executable pickle, which is exactly why a defence pipeline should demand
it -- but "no code execution on load" is not "no backdoor". A structural audit sees a
conditional subgraph or an orphaned node; it does not see a backdoor expressed purely in
the weights of an otherwise ordinary graph. For that we have to run the model.

``onnxruntime`` gives us forward inference without gradients. That is enough for the
behavioural battery, which only needs to observe how predictions move when a synthetic
trigger is stamped onto reference inputs. It is *not* enough for Neural Cleanse, which
optimises a trigger mask by gradient descent and therefore stays on the torch path. The
distinction is stated in the result rather than hidden: on an ONNX model we run the
battery and declare trigger inversion unavailable, instead of silently skipping both.

If ``onnxruntime`` is not installed on the node, this module reports that as a declared
capability gap -- the structural audit still stands, but no behavioural claim is made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np


def onnxruntime_available() -> bool:
    """Whether the node can execute ONNX graphs at all."""
    try:
        import onnxruntime  # type: ignore # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


@dataclass
class OnnxRunner:
    """A loaded ONNX inference session presented as a plain predict() callable.

    ``available`` is the single gate the caller checks. When it is False, ``notes`` and
    ``errors`` say why, and no forward pass is attempted.
    """

    available: bool = False
    input_name: str | None = None
    channels: int = 3
    height: int | None = None
    width: int | None = None
    layout: str = "NCHW"
    output_classes: int = 0
    runnable: bool = False
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    _session: Any = None

    @property
    def spatial_fixed(self) -> bool:
        return bool(self.height and self.width and self.height > 0 and self.width > 0)

    def predict(self, batch: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Run a forward pass over an NCHW float32 batch and return (argmax, confidence).

        The battery always builds NCHW; if the graph declared NHWC we transpose here so the
        battery code stays layout-agnostic. Softmax is applied defensively -- a graph that
        already ends in softmax stays a valid probability vector under a second application's
        argmax, and one that emits raw logits is normalised.
        """
        if self._session is None:
            raise RuntimeError("ONNX session is not initialised")

        array = np.asarray(batch, dtype=np.float32)
        if self.layout == "NHWC":
            array = np.transpose(array, (0, 2, 3, 1))

        outputs = self._session.run(None, {self.input_name: array})
        logits = np.asarray(outputs[0], dtype=np.float32)
        if logits.ndim == 1:
            logits = logits[None, :]
        if logits.ndim > 2:
            logits = logits.reshape(logits.shape[0], -1)

        shifted = logits - logits.max(axis=1, keepdims=True)
        exp = np.exp(shifted)
        probabilities = exp / np.clip(exp.sum(axis=1, keepdims=True), 1e-12, None)
        predicted = probabilities.argmax(axis=1)
        confidence = probabilities.max(axis=1)
        return predicted.astype(np.int64), confidence.astype(np.float32)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "runnable": self.runnable,
            "provider": "onnxruntime" if self.available else None,
            "inputName": self.input_name,
            "layout": self.layout,
            "channels": self.channels,
            "declaredHeight": self.height,
            "declaredWidth": self.width,
            "outputClasses": self.output_classes,
            "errors": self.errors,
            "notes": self.notes,
        }


def _dim(value: Any) -> int | None:
    """A concrete positive dimension, or None if the graph left it symbolic/dynamic."""
    if isinstance(value, int) and value > 0:
        return value
    return None


def load_runner(data: bytes) -> OnnxRunner:
    """Build an inference session and infer its input/output geometry.

    Returns a runner with ``available=False`` (onnxruntime missing) or ``runnable=False``
    (the graph is not a single-tensor image classifier we can drive) rather than raising, so
    the caller can record the capability gap and carry on with the structural verdict.
    """
    runner = OnnxRunner()

    try:
        import onnxruntime  # type: ignore
    except Exception:  # noqa: BLE001
        runner.notes.append(
            "onnxruntime is not installed on this node, so the model was not executed. The "
            "structural audit stands; no behavioural (trigger-response) claim is made."
        )
        return runner

    try:
        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        # Constrain execution to the CPU provider: an air-gapped inspection node has no GPU
        # and we never want the runtime reaching for a non-deterministic accelerator path.
        session = onnxruntime.InferenceSession(
            data, sess_options=options, providers=["CPUExecutionProvider"]
        )
    except Exception as exc:  # noqa: BLE001
        runner.available = True
        runner.errors.append(f"onnxruntime could not load the graph: {type(exc).__name__}: {exc}")
        return runner

    runner.available = True
    runner._session = session

    inputs = session.get_inputs()
    outputs = session.get_outputs()
    if len(inputs) != 1:
        runner.notes.append(
            f"The graph has {len(inputs)} inputs; the behavioural battery drives a single image "
            "tensor and does not run on multi-input graphs."
        )
        return runner

    inp = inputs[0]
    runner.input_name = inp.name
    shape = list(inp.shape or [])
    itype = str(getattr(inp, "type", "") or "")
    if "float" not in itype.lower():
        runner.notes.append(f"Input tensor type is {itype or 'unknown'}; the battery only drives float inputs.")
        return runner

    if len(shape) == 4:
        # NCHW if dim1 is a small channel count, else NHWC if dim3 is.
        c1, c3 = _dim(shape[1]), _dim(shape[3])
        if c1 in (1, 3):
            runner.layout = "NCHW"
            runner.channels = c1
            runner.height, runner.width = _dim(shape[2]), _dim(shape[3])
        elif c3 in (1, 3):
            runner.layout = "NHWC"
            runner.channels = c3
            runner.height, runner.width = _dim(shape[1]), _dim(shape[2])
        else:
            # Channel count is dynamic; default to 3-channel NCHW, the overwhelming norm.
            runner.layout = "NCHW"
            runner.channels = 3
            runner.height, runner.width = _dim(shape[2]), _dim(shape[3])
    else:
        runner.notes.append(
            f"Input rank is {len(shape)} (shape {shape}); the battery drives 4-D image tensors only."
        )
        return runner

    out_shape = list(outputs[0].shape or [])
    classes = _dim(out_shape[-1]) if out_shape else None
    if not classes or classes < 2:
        runner.notes.append(
            f"Output shape {out_shape} does not expose a fixed class dimension >= 2, so no "
            "classification battery can be scored against it."
        )
        return runner

    runner.output_classes = int(classes)
    runner.runnable = True
    return runner


__all__ = ["OnnxRunner", "load_runner", "onnxruntime_available"]
