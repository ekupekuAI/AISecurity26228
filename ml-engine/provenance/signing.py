"""Ed25519 keyring and detached signatures for inference records and audit blocks.

A SHA-256 digest proves a record has not changed. It does **not** prove who produced it:
anyone who can alter a record can recompute its digest. Non-repudiation needs an
asymmetric signature, which is why the problem statement asks for Ed25519 or RSA
specifically.

Design notes:

* **Ed25519** over RSA: 64-byte signatures, no parameter choices to get wrong, fast
  enough to sign every inference in a stream, and deterministic (RFC 8032) so the same
  record always yields the same signature.
* **Domain separation.** Every signature covers a context string as well as the payload.
  A signature over an inference record can then never be replayed as a signature over an
  audit block, even if an attacker could induce identical bytes.
* **Key material on disk** is written 0600 and never leaves the node. The public key and
  its fingerprint are published freely so a verifier needs nothing secret.
* **Key rotation** is supported by key id, and verification tries the named key first,
  falling back across retired keys so historical records stay verifiable after a rotation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.config import SETTINGS
from provenance.canonical import canonical_bytes

DOMAIN_INFERENCE = b"AIA-v1:inference-record"
DOMAIN_AUDIT = b"AIA-v1:audit-block"
DOMAIN_REPORT = b"AIA-v1:assurance-report"


@dataclass
class PublicKeyInfo:
    key_id: str
    algorithm: str
    public_key_b64: str
    fingerprint: str
    created_at: str
    active: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "keyId": self.key_id,
            "algorithm": self.algorithm,
            "publicKey": self.public_key_b64,
            "fingerprint": self.fingerprint,
            "createdAt": self.created_at,
            "active": self.active,
        }


class SigningUnavailable(RuntimeError):
    """Raised when no signing backend is present. Never swallowed silently."""


class Keyring:
    """Ed25519 keyring backed by a 0600 file in the node's data directory."""

    ALGORITHM = "Ed25519"

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (SETTINGS.data_dir / "keys" / "signing_keys.json")
        self._private: Any = None
        self._public: Any = None
        self._key_id: str = ""
        self._retired: dict[str, Any] = {}
        self._backend_error: str | None = None
        self._load_or_create()

    # -- lifecycle -------------------------------------------------------------

    def _load_or_create(self) -> None:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
        except Exception as exc:  # noqa: BLE001
            self._backend_error = (
                f"The 'cryptography' package is unavailable ({type(exc).__name__}), so records can be "
                "hashed but not signed. Install it to enable non-repudiation."
            )
            return

        self._path.parent.mkdir(parents=True, exist_ok=True)

        if self._path.is_file():
            try:
                document = json.loads(self._path.read_text("utf-8"))
                active = document["active"]
                self._key_id = active["keyId"]
                self._private = serialization.load_pem_private_key(
                    active["privateKeyPem"].encode("utf-8"), password=None
                )
                self._public = self._private.public_key()
                for retired in document.get("retired", []):
                    self._retired[retired["keyId"]] = serialization.load_pem_public_key(
                        retired["publicKeyPem"].encode("utf-8")
                    )
                return
            except Exception as exc:  # noqa: BLE001
                self._backend_error = f"Existing keyring could not be loaded: {type(exc).__name__}: {exc}"

        private = ed25519.Ed25519PrivateKey.generate()
        self._private = private
        self._public = private.public_key()
        self._key_id = "AIA-" + hashlib.sha256(self.public_key_bytes()).hexdigest()[:16].upper()
        self._persist(serialization)

    def _persist(self, serialization: Any) -> None:
        from core.models import utc_now

        private_pem = self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = self._public.public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        document = {
            "version": 1,
            "active": {
                "keyId": self._key_id,
                "algorithm": self.ALGORITHM,
                "privateKeyPem": private_pem,
                "publicKeyPem": public_pem,
                "createdAt": utc_now(),
            },
            "retired": [],
        }

        # Create with restrictive permissions before any content is written, so the
        # private key is never briefly world-readable.
        descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2)
        finally:
            try:
                os.chmod(self._path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                # Windows does not honour POSIX modes; the ACL inherited from the data
                # directory applies instead.
                pass

    # -- accessors -------------------------------------------------------------

    @property
    def available(self) -> bool:
        return self._private is not None

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def backend_error(self) -> str | None:
        return self._backend_error

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def public_key_info(self) -> PublicKeyInfo | None:
        if not self.available:
            return None
        from core.models import utc_now

        raw = self.public_key_bytes()
        return PublicKeyInfo(
            key_id=self._key_id,
            algorithm=self.ALGORITHM,
            public_key_b64=base64.b64encode(raw).decode("ascii"),
            fingerprint=":".join(
                hashlib.sha256(raw).hexdigest()[i : i + 4].upper() for i in range(0, 32, 4)
            ),
            created_at=utc_now(),
            active=True,
        )

    # -- operations ------------------------------------------------------------

    def sign(self, payload: bytes, domain: bytes = DOMAIN_INFERENCE) -> tuple[str, str]:
        """Sign ``domain || 0x00 || payload``. Returns (base64 signature, key id)."""
        if not self.available:
            raise SigningUnavailable(self._backend_error or "No signing key is available.")
        signature = self._private.sign(domain + b"\x00" + payload)
        return base64.b64encode(signature).decode("ascii"), self._key_id

    def verify(self, payload: bytes, signature_b64: str, key_id: str | None = None, domain: bytes = DOMAIN_INFERENCE) -> bool:
        """Verify a detached signature, trying the named key then any retired key."""
        if not self.available:
            return False
        try:
            from cryptography.exceptions import InvalidSignature

            signature = base64.b64decode(signature_b64, validate=True)
        except Exception:  # noqa: BLE001
            return False

        message = domain + b"\x00" + payload
        candidates = []
        if key_id is None or key_id == self._key_id:
            candidates.append(self._public)
        if key_id and key_id in self._retired:
            candidates.append(self._retired[key_id])
        if not candidates:
            candidates = [self._public, *self._retired.values()]

        for public_key in candidates:
            try:
                public_key.verify(signature, message)
                return True
            except InvalidSignature:
                continue
            except Exception:  # noqa: BLE001
                continue
        return False

    def sign_document(self, document: dict[str, Any], domain: bytes = DOMAIN_INFERENCE) -> tuple[str, str, str]:
        """Canonicalise, hash and sign. Returns (sha256 hex, signature, key id)."""
        payload = canonical_bytes(document)
        digest = hashlib.sha256(payload).hexdigest()
        signature, key_id = self.sign(payload, domain)
        return digest, signature, key_id


_KEYRING: Keyring | None = None


def get_keyring() -> Keyring:
    global _KEYRING
    if _KEYRING is None:
        _KEYRING = Keyring()
    return _KEYRING


__all__ = [
    "DOMAIN_AUDIT",
    "DOMAIN_INFERENCE",
    "DOMAIN_REPORT",
    "Keyring",
    "PublicKeyInfo",
    "SigningUnavailable",
    "get_keyring",
]
