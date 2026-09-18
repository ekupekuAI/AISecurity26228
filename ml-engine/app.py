"""TrustVision -- analytical engine (FastAPI).

This is the analytical core of the platform. The Node gateway owns sessions, the durable
database and the browser-facing surface; every actual inspection happens here.

Operating posture:
  * Binds to loopback by default and refuses non-trusted clients.
  * Performs no outbound network I/O at any point in a request.
  * Never returns a raw exception string; failures are correlated by request id.
  * Enforces its own upload ceilings independently of the gateway's, because a control
    that exists in only one layer is a control that can be bypassed.

Run:  python -m uvicorn app:app --app-dir ml-engine --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import logging
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any

# The engine is launched with --app-dir, so its own directory is the import root.
_ENGINE_DIR = Path(__file__).resolve().parent
if str(_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENGINE_DIR))

import asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool

from analyzers import risk_engine
from analyzers.dataset_analyzer import DatasetAnalyzer
from analyzers.model_analyzer import ModelAnalyzer
from analyzers.shift_analyzer import ShiftAnalyzer
from core import logging as structured_logging
from core.config import SETTINGS
from core.models import utc_now
from core.security import body_size_guard, service_auth_middleware
from provenance import records as provenance
from provenance.signing import get_keyring
from vision.embeddings import get_backbone

structured_logging.configure()
LOGGER = logging.getLogger("aia.engine")

app = FastAPI(
    title="TrustVision Engine",
    version="2.0.0",
    description=(
        "Dataset, model, inference-provenance and distribution-shift assurance for "
        "multi-contributor computer-vision pipelines. SIH 2026 PS SIH26228."
    ),
    docs_url="/docs" if not SETTINGS.is_production else None,
    redoc_url=None,
    openapi_url="/openapi.json" if not SETTINGS.is_production else None,
)

# No CORS middleware: the engine is never addressed by a browser. The gateway is the only
# client, and permitting cross-origin requests here would only create a bypass around it.
app.middleware("http")(service_auth_middleware)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or structured_logging.new_request_id()
    token = structured_logging.REQUEST_ID.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:  # noqa: BLE001
        LOGGER.exception("Unhandled exception in engine request")
        structured_logging.REQUEST_ID.reset(token)
        return JSONResponse(
            status_code=500,
            content={
                "error": "The assurance engine encountered an internal error.",
                "code": "ENGINE_ERROR",
                "requestId": request_id,
            },
            headers={"x-request-id": request_id},
        )

    duration = (time.perf_counter() - started) * 1000
    structured_logging.log_event(
        LOGGER,
        logging.INFO,
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        durationMs=round(duration, 2),
    )
    response.headers["x-request-id"] = request_id
    structured_logging.REQUEST_ID.reset(token)
    return response


# --- schemas ---------------------------------------------------------------------


class InferenceConfig(BaseModel):
    input_resolution: list[int] = Field(default_factory=lambda: [224, 224])
    mean_norm: list[float] = Field(default_factory=lambda: [0.485, 0.456, 0.406])
    std_norm: list[float] = Field(default_factory=lambda: [0.229, 0.224, 0.225])
    confidence_threshold: float = 0.5

    model_config = {"extra": "allow"}


class SealRequest(BaseModel):
    record_id: str | None = None
    input_image_sha256: str = Field(..., min_length=64, max_length=64)
    model_identifier: str = Field(..., min_length=1, max_length=256)
    model_sha256: str = Field(..., min_length=64, max_length=64)
    inference_config: dict[str, Any] = Field(default_factory=dict)
    prediction: str = Field(..., min_length=1, max_length=512)
    confidence: float = Field(..., ge=0.0, le=1.0)
    timestamp_utc: str | None = None
    nonce: str | None = Field(default=None, max_length=128)

    @field_validator("input_image_sha256", "model_sha256")
    @classmethod
    def _hex64(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
            raise ValueError("must be a 64-character lowercase hexadecimal SHA-256 digest")
        return cleaned


class VerifyRequest(SealRequest):
    record_sha256: str = Field(..., min_length=64, max_length=64)
    signature: str | None = None
    signing_key_id: str | None = None
    reference_document: dict[str, Any] | None = None
    check_replay: bool = True

    @field_validator("record_sha256")
    @classmethod
    def _hex64_record(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
            raise ValueError("must be a 64-character lowercase hexadecimal SHA-256 digest")
        return cleaned


class ShiftRequest(BaseModel):
    baseline_name: str = Field(default="training_baseline", max_length=200)
    target_name: str = Field(default="operational_stream", max_length=200)
    baseline_vectors: list[list[float]] | None = None
    target_vectors: list[list[float]] | None = None
    feature_names: list[str] | None = None
    baseline_features: dict[str, float] | None = None
    target_features: dict[str, float] | None = None
    baseline_class_ratios: dict[str, float] | None = None
    target_class_ratios: dict[str, float] | None = None

    @field_validator("baseline_vectors", "target_vectors")
    @classmethod
    def _bounded(cls, value: list[list[float]] | None) -> list[list[float]] | None:
        if value is None:
            return None
        # Bound the permutation test's cost: it is O(trials * n^2).
        if len(value) > 5000:
            raise ValueError("at most 5000 sample vectors per side")
        if value and len(value[0]) > 2048:
            raise ValueError("at most 2048 feature dimensions")
        return value


class GovernanceRequest(BaseModel):
    dataset_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    model_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    inference_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    shift_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    has_critical_finding: bool = False
    has_tampered_inference: bool = False
    has_confirmed_backdoor: bool = False
    has_malicious_serialization: bool = False
    has_replay_detected: bool = False
    analysis_incomplete: bool = False


# --- concurrency -----------------------------------------------------------------

#: Heavy analyses in flight at once, created lazily on the running loop.
#:
#: One, deliberately. Each analysis loads a checkpoint, pins `torch_threads` cores and
#: can hold a couple of gigabytes for its duration; Starlette's worker pool is forty
#: threads wide, so without a ceiling a burst of submissions would try to run forty of
#: those at once and exhaust memory. Serialising them also keeps the analytical path
#: single-threaded, which is what it was when every detector threshold was calibrated.
#:
#: The semaphore is built on first use, inside the handler, where a running event loop
#: exists. Constructing an asyncio.Semaphore at import time -- before uvicorn starts its
#: loop -- binds it to the wrong (or no) loop and the very first `async with` deadlocks,
#: which presents exactly as the bug this whole change set out to fix: the engine stops
#: answering. A second submission queues here rather than being refused; the gateway
#: allows fifteen minutes per call, which comfortably covers one analysis behind another.
_analysis_slots: asyncio.Semaphore | None = None


def _slots() -> asyncio.Semaphore:
    global _analysis_slots
    if _analysis_slots is None:
        _analysis_slots = asyncio.Semaphore(1)
    return _analysis_slots


async def _run_analysis(fn, *args):
    """Run a blocking analysis without stalling the event loop.

    This is not an optimisation. `DatasetAnalyzer.analyze` and `ModelAnalyzer.analyze`
    are pure CPU for fifteen to sixty seconds -- trigger inversion alone runs a bounded
    optimisation per class. Called directly from an `async def` handler they hold the
    asyncio loop for that entire time, so the engine accepts nothing else: `/health`
    goes unanswered, the gateway's 1.5 s health probe times out, and the console tells
    the operator the engine is unreachable and switches to degraded fallback -- in the
    middle of a perfectly healthy analysis. Dispatching to a worker thread keeps the
    loop free to answer the probe while the work proceeds.
    """
    async with _slots():
        return await run_in_threadpool(fn, *args)


# --- endpoints -------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, Any]:
    backbone = get_backbone()
    keyring = get_keyring()
    return {
        "status": "HEALTHY",
        "service": "TrustVision Engine",
        "version": "2.0.0",
        "timestamp": utc_now(),
        "environment": SETTINGS.environment,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "torchThreads": SETTINGS.torch_threads,
        },
        "modules": {
            "datasetEngine": "READY",
            "modelEngine": "READY" if SETTINGS.allow_model_execution else "STRUCTURAL_ONLY",
            "provenanceEngine": "READY",
            "shiftEngine": "READY",
            "riskEngine": "READY",
        },
        "capabilities": {
            "perceptualHashing": True,
            "embeddingAnalytics": backbone.available,
            "labelConsistency": backbone.available,
            "triggerConsensus": True,
            "mahalanobisOod": backbone.available,
            "neuralCleanse": SETTINGS.allow_model_execution and backbone.available,
            "behaviouralBattery": SETTINGS.allow_model_execution,
            "ed25519Signing": keyring.available,
            "mmdShift": True,
        },
        "backbone": backbone.info.to_dict(),
        "signingKey": keyring.public_key_info().to_dict() if keyring.available else None,
        "signingError": keyring.backend_error,
        "airGapped": not SETTINGS.allow_weight_download,
    }


@app.post("/analyze/dataset")
async def analyze_dataset(request: Request) -> JSONResponse:
    payload = await body_size_guard(request, SETTINGS.limits.max_upload_bytes)
    if payload is None:
        return JSONResponse(
            status_code=413,
            content={
                "error": f"Upload exceeds the {SETTINGS.limits.max_upload_bytes} byte ceiling.",
                "code": "PAYLOAD_TOO_LARGE",
            },
        )

    filename, content = _extract_multipart(payload, request.headers.get("content-type", ""))
    if content is None:
        return JSONResponse(
            status_code=400,
            content={"error": "No file part found in the multipart body.", "code": "NO_FILE"},
        )

    structured_logging.log_event(
        LOGGER, logging.INFO, "dataset analysis started", filename=filename, sizeBytes=len(content)
    )
    result = await _run_analysis(DatasetAnalyzer.analyze, filename, content)
    structured_logging.log_event(
        LOGGER,
        logging.INFO,
        "dataset analysis complete",
        filename=filename,
        status=result.get("status"),
        risk=result.get("datasetRisk"),
        findings=len(result.get("findings", [])),
        durationSeconds=result.get("analysisDurationSeconds"),
    )
    return JSONResponse(content=result)


@app.post("/analyze/model")
async def analyze_model(request: Request) -> JSONResponse:
    payload = await body_size_guard(request, SETTINGS.limits.max_model_bytes)
    if payload is None:
        return JSONResponse(
            status_code=413,
            content={
                "error": f"Model exceeds the {SETTINGS.limits.max_model_bytes} byte ceiling.",
                "code": "PAYLOAD_TOO_LARGE",
            },
        )

    filename, content = _extract_multipart(payload, request.headers.get("content-type", ""))
    if content is None:
        return JSONResponse(
            status_code=400,
            content={"error": "No file part found in the multipart body.", "code": "NO_FILE"},
        )

    structured_logging.log_event(
        LOGGER, logging.INFO, "model analysis started", filename=filename, sizeBytes=len(content)
    )
    result = await _run_analysis(ModelAnalyzer.analyze, filename, content)
    structured_logging.log_event(
        LOGGER,
        logging.INFO,
        "model analysis complete",
        filename=filename,
        status=result.get("status"),
        risk=result.get("modelRisk"),
        mode=result.get("analysisMode"),
    )
    return JSONResponse(content=result)


@app.post("/inference/seal")
def seal_inference(body: SealRequest) -> dict[str, Any]:
    record = provenance.InferenceRecord(
        record_id=body.record_id or f"INF-{int(time.time())}-{provenance.new_nonce()[:8].upper()}",
        input_image_sha256=body.input_image_sha256,
        model_identifier=body.model_identifier,
        model_sha256=body.model_sha256,
        inference_config=body.inference_config or InferenceConfig().model_dump(),
        prediction=body.prediction,
        confidence=body.confidence,
        timestamp_utc=body.timestamp_utc or utc_now(),
        nonce=body.nonce or provenance.new_nonce(),
    )
    sealed = provenance.seal(record)

    # Register the nonce at seal time so a later replay of this exact record is caught.
    provenance.get_replay_guard().check(record, sealed.record_sha256)

    structured_logging.log_event(
        LOGGER,
        logging.INFO,
        "inference sealed",
        recordId=record.record_id,
        signed=sealed.signature is not None,
    )
    return sealed.to_dict()


@app.post("/inference/verify")
def verify_inference(body: VerifyRequest) -> dict[str, Any]:
    record = provenance.InferenceRecord(
        record_id=body.record_id or "UNKNOWN",
        input_image_sha256=body.input_image_sha256,
        model_identifier=body.model_identifier,
        model_sha256=body.model_sha256,
        inference_config=body.inference_config or {},
        prediction=body.prediction,
        confidence=body.confidence,
        timestamp_utc=body.timestamp_utc or "",
        nonce=body.nonce or "",
    )

    result = provenance.verify(
        record,
        body.record_sha256,
        signature=body.signature,
        key_id=body.signing_key_id,
        reference=body.reference_document,
    )

    # Replay is only meaningful for a record that is otherwise intact: a tampered payload
    # is already disqualified and the replay verdict would only muddy the alert.
    if body.check_replay and result.status == "VERIFIED":
        verdict = provenance.get_replay_guard().check(record, result.computed_hash)
        if verdict.replayed:
            result.status = "REPLAYED"
            result.replay = verdict.to_dict()
            result.mismatches.append(verdict.reason or "Replay detected.")

    structured_logging.log_event(
        LOGGER, logging.WARNING if result.status != "VERIFIED" else logging.INFO,
        "inference verified", recordId=record.record_id, status=result.status,
    )
    return result.to_dict()


@app.post("/analyze/distribution-shift")
def analyze_shift(body: ShiftRequest) -> dict[str, Any]:
    return ShiftAnalyzer.analyze(
        baseline_name=body.baseline_name,
        target_name=body.target_name,
        baseline_vectors=body.baseline_vectors,
        target_vectors=body.target_vectors,
        feature_names=body.feature_names,
        baseline_features=body.baseline_features,
        target_features=body.target_features,
        baseline_class_ratios=body.baseline_class_ratios,
        target_class_ratios=body.target_class_ratios,
    )


@app.post("/governance/evaluate")
def evaluate_governance(body: GovernanceRequest) -> dict[str, Any]:
    composite = risk_engine.overall_risk(
        body.dataset_risk, body.model_risk, body.inference_risk, body.shift_risk
    )
    outcome = risk_engine.evaluate_governance(
        risk_engine.GovernanceInput(
            overall_risk=composite["overallRisk"],
            dataset_risk=body.dataset_risk,
            model_risk=body.model_risk,
            inference_risk=body.inference_risk,
            shift_risk=body.shift_risk,
            has_critical_finding=body.has_critical_finding,
            has_tampered_inference=body.has_tampered_inference,
            has_confirmed_backdoor=body.has_confirmed_backdoor,
            has_malicious_serialization=body.has_malicious_serialization,
            has_replay_detected=body.has_replay_detected,
            analysis_incomplete=body.analysis_incomplete,
        )
    )
    return {**composite, **outcome.to_dict(), "componentWeights": risk_engine.COMPONENT_WEIGHTS, "evaluatedAt": utc_now()}


@app.get("/provenance/public-key")
def public_key() -> dict[str, Any]:
    keyring = get_keyring()
    info = keyring.public_key_info()
    return {
        "available": keyring.available,
        "key": info.to_dict() if info else None,
        "error": keyring.backend_error,
        "canonicalization": "RFC8785-JCS",
        "schema": provenance.SCHEMA_VERSION,
    }


# --- multipart -------------------------------------------------------------------


_FILENAME_PARAM = re.compile(r';\s*filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\r\n]*))', re.IGNORECASE)


def _extract_multipart(body: bytes, content_type: str) -> tuple[str, bytes | None]:
    """Pull the first file part out of a multipart body.

    Written by hand rather than delegated to `python-multipart` because that library
    buffers or spools to a temp file, and we want the bytes to exist in exactly one place
    with a ceiling already applied. The parser is deliberately strict: anything it does
    not understand is a rejection, not a best-effort guess.

    Parameter parsing operates on the *Content-Disposition line*, not on the whole header
    block. Splitting the block on ';' lets the filename run past the end of its own line
    and absorb the following header, which turned `malicious_model.pth` into
    `...octet-stream` and made a hostile checkpoint look like an unsupported format --
    a parser bug that silently disables a security control.
    """
    if "multipart/form-data" not in content_type:
        return "upload.bin", body or None

    marker = "boundary="
    index = content_type.find(marker)
    if index < 0:
        return "upload.bin", None
    boundary = content_type[index + len(marker) :].split(";")[0].strip().strip('"')
    if not boundary:
        return "upload.bin", None

    delimiter = b"--" + boundary.encode("latin-1")

    for part in body.split(delimiter):
        if not part or part in (b"--\r\n", b"--", b"\r\n"):
            continue
        header_end = part.find(b"\r\n\r\n")
        if header_end < 0:
            continue

        header_block = part[:header_end].decode("latin-1", "replace")
        disposition = next(
            (
                line
                for line in header_block.split("\r\n")
                if line.lower().lstrip().startswith("content-disposition:")
            ),
            None,
        )
        if disposition is None or "filename" not in disposition.lower():
            continue

        match = _FILENAME_PARAM.search(disposition)
        if match is None:
            continue
        filename = (match.group(1) or match.group(2) or "").strip()
        # RFC 2616 quoted-string escaping.
        filename = filename.replace('\\"', '"').replace("\\\\", "\\")

        content = part[header_end + 4 :]
        if content.endswith(b"\r\n"):
            content = content[:-2]

        # A path in a filename is either a careless client or a traversal attempt; keep
        # only the final component, and strip anything that is not a plain filename.
        filename = filename.replace("\\", "/").split("/")[-1]
        filename = "".join(c for c in filename if c.isprintable() and c not in '<>:"|?*').strip()
        return (filename or "upload.bin"), content

    return "upload.bin", None


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(
        app,
        host=SETTINGS.host,
        port=SETTINGS.port,
        log_config=None,
        access_log=False,
    )
