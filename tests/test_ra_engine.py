# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the protocol-agnostic Remote Attestation engine.

These exercise the engine end-to-end (issue → verify_bundle) and the nonce
lifecycle (issue / consume / expiry / replay) using the in-memory verifier fake
and a ``jwt_profile`` — no TPM imports, no network.
"""

from __future__ import annotations

import pytest
from pyasn1.codec.der import encoder as der_encoder

import libattest.ra as ra_package
from libattest import get_oid_for_stmt_name
from libattest.formats.csrattest import (
    prepare_attestation_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.ra import (
    BadNonceRequest,
    NonceStore,
    ProfileRegistry,
    RemoteAttestationEngine,
    ReplayError,
    jwt_profile,
    key_attest_profile,
    tpm_profile,
)
from libattest.testing.fakes import InMemoryVerifier
from libattest.types import EarStatus, VerifyResult

OID = "1.3.6.1.4.1.99999.1"
KEY_ATTEST_OID = get_oid_for_stmt_name("key-attest")
TX = b"\x01" * 16


def _bundle(oid: str = OID, payload: bytes = b"jwt.evidence.sig", count: int = 1) -> bytes:
    """DER of a bundle with *count* opaque (JWT-style) statements under *oid*."""
    statements = [prepare_opaque_attestation_statement(oid, payload) for _ in range(count)]
    return bytes(der_encoder.encode(prepare_attestation_bundle(statements)))


def _engine(verifier) -> RemoteAttestationEngine:
    """Engine with a single jwt_profile bound to *verifier* for ``OID``."""
    profiles = ProfileRegistry()
    profiles.register(jwt_profile(request_type_oid=OID, statement_oid=OID, verifier=verifier))
    return RemoteAttestationEngine(profiles)


# ── happy path ─────────────────────────────────────────────────────────────────


def test_ra_package_does_not_reexport_raw_oid_constants() -> None:
    """GIVEN the RA package WHEN inspected THEN project OIDs are available only through accessors."""
    assert not hasattr(ra_package, "DEFAULT_EAR_EXT_OID")
    assert not hasattr(ra_package, "ID_TCG_ATTEST_CERTIFY")
    assert not hasattr(ra_package, "ID_TCG_ATTEST_QUOTE")


def test_issue_then_verify_bundle_affirming():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear.jwt.token"))
    engine = _engine(verifier)

    state = engine.issue_nonce(TX, OID)
    assert state.nonce  # a real nonce was generated
    assert state.statement_oid == OID

    outcome = engine.verify_bundle(_bundle(), TX)

    assert outcome.accepted
    assert outcome.result.per_statement[0].status == EarStatus.affirming
    assert outcome.first_ear == "ear.jwt.token"
    assert outcome.result.routes == (OID,)
    # The verifier saw the engine-issued nonce.
    assert verifier.verify_calls[0][2] == state.nonce


def test_verify_bundle_multi_statement_per_oid_instances():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    engine = _engine(verifier)

    # Two nonces for the same OID → instance 0 and 1.
    s0 = engine.issue_nonce(TX, OID)
    s1 = engine.issue_nonce(TX, OID)
    assert (s0.instance, s1.instance) == (0, 1)

    outcome = engine.verify_bundle(_bundle(count=2), TX)
    assert outcome.accepted
    assert len(outcome.result.per_statement) == 2
    consumed_nonces = {call[2] for call in verifier.verify_calls}
    assert consumed_nonces == {s0.nonce, s1.nonce}


# ── contraindicated path ────────────────────────────────────────────────────────


def test_verify_bundle_contraindicated_when_verifier_rejects():
    verifier = InMemoryVerifier(result=VerifyResult.contraindicated("bad evidence"))
    engine = _engine(verifier)

    engine.issue_nonce(TX, OID)
    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    failure = outcome.first_failure
    assert failure is not None
    assert failure.status == EarStatus.contraindicated
    assert outcome.first_ear is None


def test_key_attest_rejects_missing_subject_public_key_before_submission():
    """Key attestation must not bypass the certified-TPM-key to CSR-key binding."""
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    profiles = ProfileRegistry()
    profiles.register(
        key_attest_profile(
            request_type_oid=KEY_ATTEST_OID,
            statement_oid=KEY_ATTEST_OID,
            verifier=verifier,
        )
    )
    engine = RemoteAttestationEngine(profiles)
    engine.nonce_store.issue(TX, KEY_ATTEST_OID, session_id="key-attest-session")

    outcome = engine.verify_bundle(_bundle(oid=KEY_ATTEST_OID), TX)

    assert outcome.result.per_statement[0].status == EarStatus.contraindicated
    assert "SubjectPublicKeyInfo" in outcome.result.per_statement[0].errors[0]
    assert verifier.verify_calls == []


def test_verify_bundle_unknown_when_no_nonce_issued():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    engine = _engine(verifier)

    # No issue_nonce → consume must fail → unknown verdict, verifier untouched.
    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    assert outcome.result.per_statement[0].status == EarStatus.unknown
    assert verifier.verify_calls == []


def test_verify_bundle_unknown_for_unregistered_statement_oid():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    engine = _engine(verifier)

    other = KEY_ATTEST_OID
    # Issue under the unknown OID so the nonce consume succeeds, then the
    # missing profile yields 'unknown' (not a nonce error).
    engine.nonce_store.issue(TX, other)
    outcome = engine.verify_bundle(_bundle(oid=other), TX)

    assert outcome.result.per_statement[0].status == EarStatus.unknown
    assert verifier.verify_calls == []


def test_bundle_decode_failure_is_unknown():
    engine = _engine(InMemoryVerifier())
    outcome = engine.verify_bundle(b"\x00\x01not-der", TX)
    assert outcome.result.per_statement[0].status == EarStatus.unknown


# ── nonce lifecycle ─────────────────────────────────────────────────────────────


def test_nonce_store_issue_consume_one_shot():
    store = NonceStore()
    state = store.issue(TX, OID)
    got = store.consume(TX, OID, 0)
    assert got.nonce == state.nonce
    assert got.consumed
    # Second consume of the same slot → replay.
    with pytest.raises(ReplayError):
        store.consume(TX, OID, 0)


def test_nonce_store_unknown_slot_raises_keyerror():
    store = NonceStore()
    store.issue(TX, OID)
    with pytest.raises(KeyError):
        store.consume(TX, OID, 5)
    with pytest.raises(KeyError):
        store.consume(b"\x09" * 16, OID, 0)


def test_nonce_store_expiry():
    store = NonceStore(ttl_seconds=0)  # immediate expiry
    store.issue(TX, OID)
    # An expired nonce cannot be consumed.  The TTL=0 transaction is evicted
    # whole at consume time (KeyError), while a slot that outlives its tx window
    # raises ValueError; either signals "expired, not consumable".
    with pytest.raises((ValueError, KeyError)):
        store.consume(TX, OID, 0)


def test_nonce_store_drop_transaction():
    store = NonceStore()
    store.issue(TX, OID)
    assert store.stats()["total_nonces"] == 1
    store.drop_transaction(TX)
    assert store.stats()["total_nonces"] == 0
    with pytest.raises(KeyError):
        store.consume(TX, OID, 0)


def test_engine_drops_transaction_after_verify():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    engine = _engine(verifier)
    engine.issue_nonce(TX, OID)
    engine.verify_bundle(_bundle(), TX)
    # The per-tx state was dropped → a replayed bundle finds no nonce.
    assert engine.nonce_store.stats()["total_nonces"] == 0


def test_engine_replay_bundle_after_consume_is_unknown():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear"))
    engine = _engine(verifier)
    engine.issue_nonce(TX, OID)
    first = engine.verify_bundle(_bundle(), TX, drop_transaction=False)
    assert first.accepted
    # Replaying the same bundle without re-issuing → nonce already consumed.
    second = engine.verify_bundle(_bundle(), TX)
    assert not second.accepted
    assert second.result.per_statement[0].status == EarStatus.unknown


# ── build_nonce_response ───────────────────────────────────────────────────────


def test_build_nonce_response_same_oid_profile_echoes_request_type():
    """GIVEN a jwt_profile (one OID both ways) WHEN a response is built THEN it echoes the request type."""
    engine = _engine(InMemoryVerifier())

    response = engine.build_nonce_response(TX, OID)

    assert bytes(response["nonce"])  # a real nonce was issued
    assert str(response["respTypeInfo"]["type"]) == OID


def test_build_nonce_response_quote_profile_uses_the_distinct_response_oid():
    """GIVEN a tpm_profile (distinct req/res OIDs) WHEN a response is built THEN it uses the RESPONSE oid, not the request oid echoed back."""
    from libattest.formats.tpm import id_tpm20_quote_req, id_tpm20_quote_res

    request_oid = str(id_tpm20_quote_req)
    response_oid = str(id_tpm20_quote_res)
    assert request_oid != response_oid  # the profile under test is genuinely position-scoped

    profiles = ProfileRegistry()
    profiles.register(
        tpm_profile(
            request_type_oid=request_oid,
            statement_oid="1.3.6.1.4.1.99999.9",
            verifier=InMemoryVerifier(),
            pcrs=[0, 1, 2],
        )
    )
    engine = RemoteAttestationEngine(profiles)

    response = engine.build_nonce_response(TX, request_oid)

    assert str(response["respTypeInfo"]["type"]) == response_oid
    assert str(response["respTypeInfo"]["type"]) != request_oid


def test_build_nonce_response_unregistered_oid_falls_back_to_echo():
    """GIVEN a request type with no registered profile WHEN a response is built THEN the type is echoed back."""
    engine = _engine(InMemoryVerifier())
    other_oid = "1.3.6.1.4.1.99999.42"

    response = engine.build_nonce_response(TX, other_oid)

    assert str(response["respTypeInfo"]["type"]) == other_oid


def test_build_nonce_response_no_request_type_omits_resp_type_info():
    """GIVEN a request with no type at all WHEN a response is built THEN respTypeInfo is omitted."""
    engine = _engine(InMemoryVerifier())

    response = engine.build_nonce_response(TX, None)

    assert not response["respTypeInfo"].isValue


def test_build_nonce_response_rejects_length_below_minimum():
    """GIVEN a requested length under the minimum WHEN a response is built THEN BadNonceRequest is raised."""
    engine = _engine(InMemoryVerifier())

    with pytest.raises(BadNonceRequest):
        engine.build_nonce_response(TX, OID, requested_len=4, min_nonce_length=32)


def test_build_nonce_response_sets_expiry_when_given():
    engine = _engine(InMemoryVerifier())

    response = engine.build_nonce_response(TX, OID, expiry_time=50)

    assert int(response["expiry"]) == 50


# ── first_ear_extension ─────────────────────────────────────────────────────────


def test_first_ear_extension_resolves_the_affirming_statements_profile():
    verifier = InMemoryVerifier(result=VerifyResult.affirming("ear.jwt.token"))
    engine = _engine(verifier)
    engine.issue_nonce(TX, OID)

    outcome = engine.verify_bundle(_bundle(), TX)

    assert outcome.accepted
    ext = outcome.first_ear_extension
    assert ext is not None
    oid_dot, extn_der = ext
    assert isinstance(oid_dot, str)
    assert isinstance(extn_der, bytes)
    assert extn_der  # non-empty DER


def test_first_ear_extension_is_none_when_nothing_affirmed():
    verifier = InMemoryVerifier(result=VerifyResult.contraindicated("bad evidence"))
    engine = _engine(verifier)
    engine.issue_nonce(TX, OID)

    outcome = engine.verify_bundle(_bundle(), TX)

    assert not outcome.accepted
    assert outcome.first_ear_extension is None


def test_first_ear_extension_is_none_on_bundle_decode_failure():
    engine = _engine(InMemoryVerifier())

    outcome = engine.verify_bundle(b"\x00\x01not-a-bundle", TX)

    assert outcome.first_ear_extension is None
