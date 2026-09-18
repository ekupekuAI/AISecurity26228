"""Canonical inference records: sealing, verification, and replay defence.

The problem statement asks for "a verifiable cryptographic binding among the input image,
model identifier or weight digest, preprocessing and inference configuration, and
resulting output". That binding is this module.

A sealed record commits to all five elements at once. Changing any of them -- swapping
the model, altering the preprocessing, or rewriting STOP_SIGN to SPEED_LIMIT in transit
-- changes the canonical bytes and therefore the digest, and the Ed25519 signature makes
the change attributable rather than merely visible.

Three distinct attacks are separated in the verification result, because the response to
each differs:

* **Alteration** -- digest mismatch. The payload changed after sealing.
* **Forgery** -- digest matches but the signature does not verify. Someone recomputed the
  hash without the private key, which is exactly what a hash-only scheme cannot catch.
* **Replay** -- the record is internally perfect but its nonce was already consumed. A
  captured "all clear" is being re-sent to mask a live situation.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.models import utc_now
from provenance.canonical import canonical_bytes, canonicalize
from provenance.signing import DOMAIN_INFERENCE, SigningUnavailable, get_keyring

#: Fields that constitute the binding. Ordering is irrelevant (JCS sorts), but the set is
#: fixed: adding a field later changes every digest, so the schema is versioned.
SCHEMA_VERSION = "aia-inference/1"

#: A record whose timestamp is further than this from the verifier's clock is stale.
#: Generous because air-gapped nodes drift, but bounded so a months-old capture is caught.
MAX_CLOCK_SKEW_SECONDS = 24 * 60 * 60


@dataclass
class InferenceRecord:
    record_id: str
    input_image_sha256: str
    model_identifier: str
    model_sha256: str
    inference_config: dict[str, Any]
    prediction: str
    confidence: float
    timestamp_utc: str
    nonce: str
    schema: str = SCHEMA_VERSION

    def to_canonical_document(self) -> dict[str, Any]:
        """The exact object that gets canonicalised, hashed and signed.

        The digest and signature are deliberately absent: a commitment cannot cover
        itself.
        """
        return {
            "schema": self.schema,
            "recordId": self.record_id,
            "inputImageSha256": self.input_image_sha256.strip().lower(),
            "modelIdentifier": self.model_identifier.strip(),
            "modelSha256": self.model_sha256.strip().lower(),
            "inferenceConfig": self.inference_config,
            "prediction": self.prediction.strip(),
            # Fixed precision: 0.1+0.2 must not produce a different digest than 0.3.
            "confidence": round(float(self.confidence), 6),
            "timestampUtc": self.timestamp_utc.strip(),
            "nonce": self.nonce.strip(),
        }


@dataclass
class SealedRecord:
    record: InferenceRecord
    canonical: str
    record_sha256: str
    signature: str | None
    key_id: str | None
    signing_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        document = self.record.to_canonical_document()
        return {
            **document,
            "recordSha256": self.record_sha256,
            "signature": self.signature,
            "signingKeyId": self.key_id,
            "signatureAlgorithm": "Ed25519" if self.signature else None,
            "canonicalization": "RFC8785-JCS",
            "canonicalString": self.canonical,
            "signingError": self.signing_error,
            "sealedAt": utc_now(),
        }


@dataclass
class VerificationResult:
    status: str  # VERIFIED | TAMPERED | FORGED | REPLAYED | UNVERIFIABLE
    computed_hash: str
    expected_hash: str
    canonical_string: str
    signature_valid: bool | None
    mismatches: list[str] = field(default_factory=list)
    altered_fields: list[str] = field(default_factory=list)
    replay: dict[str, Any] | None = None
    verified_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "computedHash": self.computed_hash,
            "expectedHash": self.expected_hash,
            "canonicalString": self.canonical_string,
            "signatureValid": self.signature_valid,
            "mismatches": self.mismatches,
            "alteredFields": self.altered_fields,
            "replay": self.replay,
            "verifiedAt": self.verified_at,
        }


def new_nonce() -> str:
    """128 bits from the OS CSPRNG. Never a counter or a timestamp."""
    return secrets.token_hex(16)


def seal(record: InferenceRecord) -> SealedRecord:
    """Canonicalise, hash and sign an inference record."""
    document = record.to_canonical_document()
    canonical = canonicalize(document)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    signature: str | None = None
    key_id: str | None = None
    error: str | None = None
    try:
        keyring = get_keyring()
        signature, key_id = keyring.sign(canonical.encode("utf-8"), DOMAIN_INFERENCE)
    except SigningUnavailable as exc:
        # Surfaced, never swallowed: an unsigned record is a weaker artefact and the
        # operator must know it.
        error = str(exc)

    return SealedRecord(
        record=record,
        canonical=canonical,
        record_sha256=digest,
        signature=signature,
        key_id=key_id,
        signing_error=error,
    )


def verify(
    record: InferenceRecord,
    expected_hash: str,
    signature: str | None = None,
    key_id: str | None = None,
    *,
    reference: dict[str, Any] | None = None,
) -> VerificationResult:
    """Verify a record against its recorded digest and signature.

    `reference` is the originally sealed document when available; supplying it lets us
    name exactly which fields changed rather than only reporting a digest mismatch, which
    is the difference between an alert an analyst can act on and one they cannot.
    """
    document = record.to_canonical_document()
    canonical = canonicalize(document)
    computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    expected_normalised = (expected_hash or "").strip().lower()
    hash_matches = bool(expected_normalised) and secrets.compare_digest(computed, expected_normalised)

    mismatches: list[str] = []
    altered: list[str] = []

    if not hash_matches:
        mismatches.append(
            f"Canonical digest mismatch: recorded {expected_normalised[:16]}..., recomputed "
            f"{computed[:16]}.... At least one bound field was modified after sealing."
        )
        if reference:
            for key, original in reference.items():
                if key in {"recordSha256", "signature", "signingKeyId", "canonicalString"}:
                    continue
                current = document.get(key)
                if current != original:
                    altered.append(key)
                    mismatches.append(f"Field '{key}': sealed as {original!r}, presented as {current!r}.")

    signature_valid: bool | None = None
    if signature:
        keyring = get_keyring()
        if keyring.available:
            signature_valid = keyring.verify(canonical.encode("utf-8"), signature, key_id, DOMAIN_INFERENCE)
        else:
            mismatches.append("Signature present but no verification key is available on this node.")

    # A matching digest with a failing signature is the interesting case: the payload is
    # internally consistent, which means someone recomputed the hash. Only the private
    # key holder can produce a valid signature, so this is forgery, not corruption.
    if hash_matches and signature and signature_valid is False:
        return VerificationResult(
            status="FORGED",
            computed_hash=computed,
            expected_hash=expected_normalised,
            canonical_string=canonical,
            signature_valid=False,
            mismatches=[
                "The digest matches but the Ed25519 signature does not verify. The record was "
                "re-hashed by a party without the signing key: this is forgery, not transmission "
                "corruption."
            ],
        )

    if not hash_matches:
        return VerificationResult(
            status="TAMPERED",
            computed_hash=computed,
            expected_hash=expected_normalised,
            canonical_string=canonical,
            signature_valid=signature_valid,
            mismatches=mismatches,
            altered_fields=altered,
        )

    if signature is None:
        return VerificationResult(
            status="VERIFIED",
            computed_hash=computed,
            expected_hash=expected_normalised,
            canonical_string=canonical,
            signature_valid=None,
            mismatches=[
                "Digest verified. No signature accompanied this record, so integrity is confirmed "
                "but origin is not: a party able to alter the record could also recompute its digest."
            ],
        )

    return VerificationResult(
        status="VERIFIED",
        computed_hash=computed,
        expected_hash=expected_normalised,
        canonical_string=canonical,
        signature_valid=signature_valid,
    )


# --- replay and substitution defence ---------------------------------------------


@dataclass
class ReplayVerdict:
    replayed: bool
    reason: str | None = None
    first_seen: str | None = None
    detail: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "replayed": self.replayed,
            "reason": self.reason,
            "firstSeen": self.first_seen,
            "detail": self.detail,
        }


class ReplayGuard:
    """In-memory nonce ledger with substitution and staleness detection.

    The engine holds the hot window; the Node gateway persists the authoritative ledger
    in SQLite. Both must agree, so the rules live here and the gateway mirrors them.
    """

    def __init__(self, capacity: int = 200_000) -> None:
        self._nonces: dict[str, tuple[float, str, str]] = {}  # nonce -> (seen_at, record_id, digest)
        self._bindings: dict[tuple[str, str], tuple[str, str]] = {}  # (input,model) -> (prediction, record_id)
        self._capacity = capacity

    def check(self, record: InferenceRecord, digest: str) -> ReplayVerdict:
        now = time.time()
        nonce = record.nonce.strip()

        previous = self._nonces.get(nonce)
        if previous is not None:
            seen_at, previous_id, previous_digest = previous
            if previous_digest == digest:
                return ReplayVerdict(
                    replayed=True,
                    reason=(
                        "Nonce and digest both match a record already accepted by this node. The "
                        "payload is a verbatim replay of an earlier inference; an adversary may be "
                        "re-sending a stale all-clear to mask current conditions."
                    ),
                    first_seen=datetime.fromtimestamp(seen_at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    detail={"originalRecordId": previous_id, "nonce": nonce},
                )
            return ReplayVerdict(
                replayed=True,
                reason=(
                    "Nonce reuse with a different payload. A nonce must be unique per record; "
                    "reuse means either a broken generator or a deliberate attempt to make a "
                    "substituted payload look freshly sealed."
                ),
                first_seen=datetime.fromtimestamp(seen_at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                detail={"originalRecordId": previous_id, "nonce": nonce, "originalDigest": previous_digest},
            )

        # Same image, same model, different answer: one of the two records is a fabrication.
        binding_key = (record.input_image_sha256.strip().lower(), record.model_sha256.strip().lower())
        binding = self._bindings.get(binding_key)
        if binding is not None and binding[0] != record.prediction.strip():
            self._remember(nonce, now, record, digest, binding_key)
            return ReplayVerdict(
                replayed=True,
                reason=(
                    f"Output substitution: this input and model previously produced "
                    f"'{binding[0]}' (record {binding[1]}) and now produce "
                    f"'{record.prediction.strip()}'. A deterministic pipeline cannot do both."
                ),
                detail={
                    "previousPrediction": binding[0],
                    "previousRecordId": binding[1],
                    "currentPrediction": record.prediction.strip(),
                },
            )

        staleness = _staleness_seconds(record.timestamp_utc)
        if staleness is not None and abs(staleness) > MAX_CLOCK_SKEW_SECONDS:
            self._remember(nonce, now, record, digest, binding_key)
            direction = "in the future" if staleness < 0 else "old"
            return ReplayVerdict(
                replayed=True,
                reason=(
                    f"Record timestamp is {abs(staleness) / 3600:.1f} hours {direction}, beyond the "
                    f"{MAX_CLOCK_SKEW_SECONDS / 3600:.0f}-hour tolerance. Either the node clocks have "
                    "diverged or a captured record is being re-injected."
                ),
                detail={"timestampUtc": record.timestamp_utc, "skewSeconds": round(staleness, 1)},
            )

        self._remember(nonce, now, record, digest, binding_key)
        return ReplayVerdict(replayed=False)

    def _remember(
        self,
        nonce: str,
        now: float,
        record: InferenceRecord,
        digest: str,
        binding_key: tuple[str, str],
    ) -> None:
        if len(self._nonces) >= self._capacity:
            # Evict the oldest decile rather than one entry, so eviction is amortised.
            oldest = sorted(self._nonces.items(), key=lambda kv: kv[1][0])[: self._capacity // 10]
            for key, _ in oldest:
                self._nonces.pop(key, None)
        self._nonces[nonce] = (now, record.record_id, digest)
        self._bindings[binding_key] = (record.prediction.strip(), record.record_id)

    @property
    def size(self) -> int:
        return len(self._nonces)


def _staleness_seconds(timestamp: str) -> float | None:
    try:
        text = timestamp.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - parsed).total_seconds()
    except (ValueError, AttributeError):
        return None


_GUARD: ReplayGuard | None = None


def get_replay_guard() -> ReplayGuard:
    global _GUARD
    if _GUARD is None:
        _GUARD = ReplayGuard()
    return _GUARD


__all__ = [
    "InferenceRecord",
    "MAX_CLOCK_SKEW_SECONDS",
    "ReplayGuard",
    "ReplayVerdict",
    "SCHEMA_VERSION",
    "SealedRecord",
    "VerificationResult",
    "get_replay_guard",
    "new_nonce",
    "seal",
    "verify",
]
