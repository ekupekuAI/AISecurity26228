"""
Cryptographic Provenance Engine
Calculates and verifies tamper-proof SHA-256 signatures for inference records.
"""

import hashlib
import json
from typing import Dict, Any, Tuple, List

class ProvenanceEngine:
    @staticmethod
    def canonicalize_record(
        input_image_hash: str,
        model_identifier: str,
        model_sha256: str,
        preprocessing_config: str,
        prediction: str,
        confidence: float,
        timestamp: str,
        nonce: str
    ) -> str:
        """
        Builds a canonical, deterministic representation of the inference record.
        """
        # Normalize preprocessing_config string if JSON
        clean_preproc = preprocessing_config.strip()
        try:
            parsed = json.loads(clean_preproc)
            clean_preproc = json.dumps(parsed, sort_keys=True)
        except Exception:
            clean_preproc = clean_preproc.replace("\r\n", "\n").strip()

        # Format confidence with fixed 6 decimal precision
        conf_str = f"{float(confidence):.6f}"

        components = [
            input_image_hash.strip().lower(),
            model_identifier.strip(),
            model_sha256.strip().lower(),
            clean_preproc,
            prediction.strip(),
            conf_str,
            timestamp.strip(),
            nonce.strip()
        ]
        return "||".join(components)

    @classmethod
    def generate_record_hash(cls, **kwargs) -> Tuple[str, str]:
        canonical_str = cls.canonicalize_record(**kwargs)
        hasher = hashlib.sha256()
        hasher.update(canonical_str.encode("utf-8"))
        record_hash = hasher.hexdigest()
        return record_hash, canonical_str

    @classmethod
    def verify_record(
        cls,
        expected_hash: str,
        input_image_hash: str,
        model_identifier: str,
        model_sha256: str,
        preprocessing_config: str,
        prediction: str,
        confidence: float,
        timestamp: str,
        nonce: str
    ) -> Dict[str, Any]:
        """
        Verifies whether an inference record matches its cryptographic hash.
        Returns VERIFIED or TAMPERED, with granular mismatch details.
        """
        computed_hash, canonical_str = cls.generate_record_hash(
            input_image_hash=input_image_hash,
            model_identifier=model_identifier,
            model_sha256=model_sha256,
            preprocessing_config=preprocessing_config,
            prediction=prediction,
            confidence=confidence,
            timestamp=timestamp,
            nonce=nonce
        )

        is_valid = (computed_hash.lower() == expected_hash.strip().lower())
        mismatches: List[str] = []

        if not is_valid:
            mismatches.append(
                f"Record hash discrepancy: expected {expected_hash}, computed {computed_hash}."
            )

        return {
            "status": "VERIFIED" if is_valid else "TAMPERED",
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "canonical_string": canonical_str,
            "is_valid": is_valid,
            "mismatches": mismatches
        }
