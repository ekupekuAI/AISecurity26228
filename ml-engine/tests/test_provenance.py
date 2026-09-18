"""Provenance tests: canonicalisation, sealing, tamper classes and replay.

The tamper tests walk the PS case study directly: a record sealed as STOP_SIGN and
re-presented as SPEED_LIMIT must fail verification and name the field that changed.
"""

from __future__ import annotations

import pytest

from provenance import records as prov
from provenance.canonical import canonicalize, serialize_number
from provenance.signing import DOMAIN_AUDIT, DOMAIN_INFERENCE, get_keyring


def make_record(**overrides) -> prov.InferenceRecord:
    base = dict(
        record_id="INF-20260913-00941",
        input_image_sha256="a" * 64,
        model_identifier="traffic_recon_resnet18.pth",
        model_sha256="b" * 64,
        inference_config={
            "input_resolution": [224, 224],
            "mean_norm": [0.485, 0.456, 0.406],
            "std_norm": [0.229, 0.224, 0.225],
            "confidence_threshold": 0.5,
        },
        prediction="STOP_SIGN",
        confidence=0.9841,
        timestamp_utc="2026-09-13T06:18:22Z",
        nonce="99382104",
    )
    base.update(overrides)
    return prov.InferenceRecord(**base)


class TestCanonicalization:
    def test_key_order_does_not_change_output(self) -> None:
        assert canonicalize({"b": 1, "a": 2}) == canonicalize({"a": 2, "b": 1})

    def test_output_has_no_insignificant_whitespace(self) -> None:
        assert canonicalize({"a": [1, 2], "b": {"c": 3}}) == '{"a":[1,2],"b":{"c":3}}'

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(1, "1"), (1.0, "1"), (-0.0, "0"), (0.5, "0.5"), (1e21, "1e+21"), (100.0, "100")],
    )
    def test_numbers_render_like_javascript(self, value, expected) -> None:
        assert serialize_number(value) == expected

    def test_nan_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            serialize_number(float("nan"))

    def test_separator_injection_cannot_forge_a_collision(self) -> None:
        """The failure mode of a delimiter-joined scheme, which JCS structurally prevents."""
        a = canonicalize({"prediction": "STOP", "confidence": "0.99"})
        b = canonicalize({"prediction": "STOP||0.99", "confidence": ""})
        assert a != b

    def test_unicode_is_escaped_minimally(self) -> None:
        assert canonicalize({"k": "café"}) == '{"k":"café"}'
        assert canonicalize({"k": "line\nbreak"}) == '{"k":"line\\nbreak"}'


class TestSealAndVerify:
    def test_sealed_record_verifies(self) -> None:
        record = make_record()
        sealed = prov.seal(record)

        assert len(sealed.record_sha256) == 64
        result = prov.verify(record, sealed.record_sha256, sealed.signature, sealed.key_id)

        assert result.status == "VERIFIED"
        if sealed.signature:
            assert result.signature_valid is True

    def test_altered_prediction_is_detected_and_named(self) -> None:
        """The PS case study: STOP_SIGN rewritten to SPEED_LIMIT in transit."""
        original = make_record()
        sealed = prov.seal(original)
        reference = original.to_canonical_document()

        tampered = make_record(prediction="SPEED_LIMIT")
        result = prov.verify(
            tampered, sealed.record_sha256, sealed.signature, sealed.key_id, reference=reference
        )

        assert result.status == "TAMPERED"
        assert "prediction" in result.altered_fields
        assert any("SPEED_LIMIT" in m for m in result.mismatches)

    @pytest.mark.parametrize(
        "field",
        ["input_image_sha256", "model_sha256", "confidence", "timestamp_utc", "nonce", "model_identifier"],
    )
    def test_every_bound_field_is_covered(self, field: str) -> None:
        """Each element of the binding must independently break the digest."""
        original = make_record()
        sealed = prov.seal(original)

        mutations = {
            "input_image_sha256": "c" * 64,
            "model_sha256": "d" * 64,
            "confidence": 0.5,
            "timestamp_utc": "2026-09-13T07:00:00Z",
            "nonce": "00000001",
            "model_identifier": "other_model.pth",
        }
        tampered = make_record(**{field: mutations[field]})
        result = prov.verify(tampered, sealed.record_sha256)

        assert result.status == "TAMPERED", f"{field} is not covered by the digest"

    def test_preprocessing_change_breaks_the_seal(self) -> None:
        original = make_record()
        sealed = prov.seal(original)

        tampered = make_record(
            inference_config={
                "input_resolution": [224, 224],
                "mean_norm": [0.0, 0.0, 0.0],
                "std_norm": [1.0, 1.0, 1.0],
                "confidence_threshold": 0.5,
            }
        )
        assert prov.verify(tampered, sealed.record_sha256).status == "TAMPERED"

    def test_recomputed_hash_without_the_key_is_forgery(self) -> None:
        """A hash-only scheme passes this. A signed scheme must not."""
        keyring = get_keyring()
        if not keyring.available:
            pytest.skip("cryptography backend unavailable")

        original = make_record()
        sealed = prov.seal(original)

        # The attacker alters the record AND recomputes a correct digest, but cannot
        # produce a matching signature.
        forged = make_record(prediction="SPEED_LIMIT")
        forged_sealed = prov.seal(forged)

        result = prov.verify(
            forged, forged_sealed.record_sha256, sealed.signature, sealed.key_id
        )

        assert result.status == "FORGED"
        assert result.signature_valid is False

    def test_unsigned_record_is_verified_but_caveated(self) -> None:
        record = make_record()
        sealed = prov.seal(record)
        result = prov.verify(record, sealed.record_sha256, signature=None)

        assert result.status == "VERIFIED"
        assert result.signature_valid is None
        assert any("origin is not" in m for m in result.mismatches)


class TestSigning:
    def test_signature_verifies_and_rejects_a_flipped_bit(self) -> None:
        keyring = get_keyring()
        if not keyring.available:
            pytest.skip("cryptography backend unavailable")

        payload = b"operational payload"
        signature, key_id = keyring.sign(payload, DOMAIN_INFERENCE)

        assert keyring.verify(payload, signature, key_id, DOMAIN_INFERENCE)
        assert not keyring.verify(b"operational payloae", signature, key_id, DOMAIN_INFERENCE)

    def test_domain_separation_blocks_cross_context_replay(self) -> None:
        """An inference signature must not be reusable as an audit-block signature."""
        keyring = get_keyring()
        if not keyring.available:
            pytest.skip("cryptography backend unavailable")

        payload = b"same bytes, different meaning"
        signature, key_id = keyring.sign(payload, DOMAIN_INFERENCE)

        assert keyring.verify(payload, signature, key_id, DOMAIN_INFERENCE)
        assert not keyring.verify(payload, signature, key_id, DOMAIN_AUDIT)

    def test_public_key_is_publishable(self) -> None:
        keyring = get_keyring()
        if not keyring.available:
            pytest.skip("cryptography backend unavailable")

        info = keyring.public_key_info()
        assert info is not None
        assert info.algorithm == "Ed25519"
        assert info.fingerprint.count(":") == 7


class TestReplayGuard:
    def test_first_use_of_a_nonce_is_accepted(self) -> None:
        guard = prov.ReplayGuard()
        record = make_record(nonce=prov.new_nonce(), timestamp_utc=prov.utc_now())
        assert guard.check(record, "digest-1").replayed is False

    def test_verbatim_replay_is_caught(self) -> None:
        guard = prov.ReplayGuard()
        record = make_record(nonce="fixed-nonce", timestamp_utc=prov.utc_now())

        assert guard.check(record, "digest-1").replayed is False
        verdict = guard.check(record, "digest-1")

        assert verdict.replayed is True
        assert "verbatim replay" in (verdict.reason or "")

    def test_nonce_reuse_with_a_new_payload_is_caught(self) -> None:
        guard = prov.ReplayGuard()
        first = make_record(nonce="shared", timestamp_utc=prov.utc_now())
        guard.check(first, "digest-1")

        verdict = guard.check(make_record(nonce="shared", prediction="OTHER"), "digest-2")

        assert verdict.replayed is True
        assert "Nonce reuse" in (verdict.reason or "")

    def test_output_substitution_is_caught(self) -> None:
        """Same image, same model, different answer: one of the two is fabricated."""
        guard = prov.ReplayGuard()
        guard.check(make_record(nonce="n1", timestamp_utc=prov.utc_now()), "d1")

        verdict = guard.check(
            make_record(nonce="n2", prediction="SPEED_LIMIT", timestamp_utc=prov.utc_now()), "d2"
        )

        assert verdict.replayed is True
        assert "substitution" in (verdict.reason or "").lower()

    def test_stale_timestamp_is_caught(self) -> None:
        guard = prov.ReplayGuard()
        verdict = guard.check(
            make_record(nonce=prov.new_nonce(), timestamp_utc="2020-01-01T00:00:00Z"), "d1"
        )

        assert verdict.replayed is True
        assert "hours old" in (verdict.reason or "")

    def test_new_nonces_are_unique(self) -> None:
        assert len({prov.new_nonce() for _ in range(2000)}) == 2000
