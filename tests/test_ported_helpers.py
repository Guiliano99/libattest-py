# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the format helpers ported into Updatev7 for the RA engine.

Covers the csrattest decode/unwrap helpers, the EAR-extension encoders, and the
TPM ports (``decode_tcg_attest_certify`` / ``id_tcg_attest_quote`` /
``make_pcr_selection_resp_info`` + the respInfo JSON registry).  The TPM block
is skipped when the TPM format stack cannot import (e.g. ``tpm2_pytss`` native
lib missing) — but the stub installed by ``conftest`` normally makes it run.
"""

from __future__ import annotations

import pytest
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ

from libattest.formats.csrattest import (
    AttestationStatement,
    decode_attestation_bundle,
    decode_attestation_statement,
    encode_oid_der,
    prepare_asn1_attestation_statement,
    prepare_attestation_bundle,
    prepare_multi_statement_bundle,
    prepare_opaque_attestation_statement,
    unwrap_attestation_statement,
)
from libattest.x509 import (
    CMW,
    ID_PE_CMW_DOTTED,
    encode_ear_extension,
    unwrap_context_tag,
    wrap_ear_in_cmw_json,
)

OID = "2.23.133.20.2"


# ── csrattest decode / unwrap ────────────────────────────────────────────────────


def test_decode_attestation_bundle_round_trip():
    st = prepare_opaque_attestation_statement(OID, b"payload")
    der = bytes(der_encoder.encode(prepare_attestation_bundle([st])))
    bundle = decode_attestation_bundle(der)
    assert len(bundle["attestations"]) == 1
    assert str(bundle["attestations"][0]["type"]) == OID


def test_decode_attestation_bundle_rejects_trailing_bytes():
    st = prepare_opaque_attestation_statement(OID, b"payload")
    der = bytes(der_encoder.encode(prepare_attestation_bundle([st])))
    with pytest.raises(ValueError):
        decode_attestation_bundle(der + b"\x00")


def test_decode_attestation_statement_round_trip():
    st = prepare_opaque_attestation_statement(OID, b"payload")
    der = bytes(der_encoder.encode(st))
    decoded = decode_attestation_statement(der)
    assert isinstance(decoded, AttestationStatement)
    assert str(decoded["type"]) == OID


def test_unwrap_octet_string_wrapped_statement():
    st = prepare_opaque_attestation_statement(OID, b"jwt.payload.sig")
    bundle = decode_attestation_bundle(bytes(der_encoder.encode(prepare_attestation_bundle([st]))))
    inner, is_wrapped = unwrap_attestation_statement(bytes(bundle["attestations"][0]["stmt"]))
    assert is_wrapped is True
    assert inner == b"jwt.payload.sig"


def test_unwrap_asn1_statement_returns_verbatim():
    seq = bytes(der_encoder.encode(univ.Sequence()))  # 0x30 0x00
    st = prepare_asn1_attestation_statement(OID, seq)
    bundle = decode_attestation_bundle(bytes(der_encoder.encode(prepare_attestation_bundle([st]))))
    inner, is_wrapped = unwrap_attestation_statement(bytes(bundle["attestations"][0]["stmt"]))
    assert is_wrapped is False
    assert inner == seq


def test_encode_oid_der_matches_pyasn1():
    expected = bytes(der_encoder.encode(univ.ObjectIdentifier(OID)))
    assert encode_oid_der(OID) == expected
    assert encode_oid_der(univ.ObjectIdentifier(OID)) == expected


class _Result:
    def __init__(self, oid, evidence, is_asn1_evidence):
        self.oid = oid
        self._evidence = evidence
        self.is_asn1_evidence = is_asn1_evidence

    def evidence_bytes(self):
        return self._evidence


def test_prepare_multi_statement_bundle_honors_is_asn1_evidence():
    seq = bytes(der_encoder.encode(univ.Sequence()))
    results = [
        _Result(OID, b"opaque-jwt", is_asn1_evidence=False),
        _Result("2.23.133.20.1", seq, is_asn1_evidence=True),
    ]
    bundle = prepare_multi_statement_bundle(results)
    decoded = decode_attestation_bundle(bytes(der_encoder.encode(bundle)))
    stmts = list(decoded["attestations"])
    # First: opaque → OCTET STRING wrapper stripped on unwrap.
    inner0, wrapped0 = unwrap_attestation_statement(bytes(stmts[0]["stmt"]))
    assert (wrapped0, inner0) == (True, b"opaque-jwt")
    # Second: asn1 → embedded verbatim, no wrapper.
    inner1, wrapped1 = unwrap_attestation_statement(bytes(stmts[1]["stmt"]))
    assert (wrapped1, inner1) == (False, seq)


# ── EAR-extension encoders ───────────────────────────────────────────────────────


def test_encode_ear_extension_raw_oid():
    oid, value = encode_ear_extension("a.b.c", oid="1.7.6.5.123")
    assert oid == "1.7.6.5.123"
    assert value == b"a.b.c"


def test_encode_ear_extension_cmw_oid_wraps_record():
    oid, value = encode_ear_extension("a.b.c", oid=ID_PE_CMW_DOTTED)
    assert oid == ID_PE_CMW_DOTTED
    cmw, _ = der_decoder.decode(value, asn1Spec=CMW())
    assert cmw.getName() == "json"
    # CMW JSON record: [media-type, base64url-nopad(jwt)].
    assert str(cmw["json"]).startswith('["application/eat+jwt",')


def test_wrap_ear_in_cmw_json_is_der_of_cmw():
    value = wrap_ear_in_cmw_json("x.y.z")
    cmw, rest = der_decoder.decode(value, asn1Spec=CMW())
    assert rest == b""
    assert cmw.getName() == "json"


def test_unwrap_context_tag_passthrough_for_sequence():
    der = bytes(der_encoder.encode(univ.Sequence()))  # starts with 0x30
    assert unwrap_context_tag(der) == der


def test_unwrap_context_tag_strips_explicit_tag():
    inner = bytes(der_encoder.encode(univ.Sequence()))  # 0x30 0x00
    # Wrap in an EXPLICIT [0] context tag: A0 len <inner>.
    explicit = bytes([0xA0, len(inner)]) + inner
    assert unwrap_context_tag(explicit) == inner


# ── TPM ports (skipped if the TPM format stack cannot import) ────────────────────

tpm_formats = pytest.importorskip(
    "libattest.formats.tpm",
    reason="TPM format stack unavailable",
)
respinfo = pytest.importorskip("libattest.formats.respinfo")


def test_id_tcg_attest_quote_value():
    assert str(tpm_formats.id_tcg_attest_quote) == "2.23.133.20.2"


def test_decode_tcg_attest_certify_round_trip():
    built = tpm_formats.prepare_tcg_attest_certify(b"attest-bytes", b"sig-bytes")
    der = bytes(der_encoder.encode(built))
    decoded = tpm_formats.decode_tcg_attest_certify(der)
    assert bytes(decoded["tpmSAttest"]) == b"attest-bytes"
    assert bytes(decoded["signature"]) == b"sig-bytes"


def test_make_pcr_selection_resp_info_round_trips_via_registry():
    der = bytes(tpm_formats.tpm20_quote_response_info(pcr_selection=[0, 1, 2, 3, 4], hash_algo=0x000B))
    as_json = respinfo.DEFAULT_RESP_INFO_REGISTRY.to_json("2.23.133.20.2", der)
    assert as_json == {"pcrSelection": [0, 1, 2, 3, 4], "hashAlgo": 11}
    back = respinfo.DEFAULT_RESP_INFO_REGISTRY.from_json("2.23.133.20.2", as_json)
    assert bytes(back) == der


def test_respinfo_registry_unknown_oid_raises():
    with pytest.raises(KeyError):
        respinfo.DEFAULT_RESP_INFO_REGISTRY.to_json("1.2.3.4", b"\x30\x00")


def test_tpm_profile_engine_forwards_resp_info_json():
    """tpm_profile builds a respInfo and the engine forwards it as JSON.

    Exercises the lazy TPM import inside ``tpm_profile`` and the engine's
    respInfo DER→JSON hop, using a ``VeraisonVerifierClient`` subclass whose
    ``submit_evidence`` is captured (no network).
    """
    from libattest.ra import (
        ProfileRegistry,
        RemoteAttestationEngine,
        VeraisonVerifierClient,
        tpm_profile,
    )

    captured: dict = {}

    class CapturingClient(VeraisonVerifierClient):
        def submit_evidence(self, nonce, evidence, evidence_oid=None, resp_info_json=None):
            captured.update(
                nonce=nonce, evidence=evidence, oid=evidence_oid, resp_info_json=resp_info_json
            )
            return "tpm.ear.jwt"

    quote_oid = "2.23.133.20.2"
    profiles = ProfileRegistry()
    profiles.register(
        tpm_profile(
            request_type_oid="1.3.6.1.4.1.99999.5",  # PCR-selection syntax OID
            statement_oid=quote_oid,
            verifier=CapturingClient(base_url="http://verifier.invalid"),
            pcrs=[0, 1, 2, 3, 4],
        )
    )
    engine = RemoteAttestationEngine(profiles)

    tx = b"\x0b" * 16
    req_info = tpm_formats.encode_tpm20_quote_req_info(supported_hash_algos=[0x000B])
    state = engine.issue_nonce(tx, "1.3.6.1.4.1.99999.5", req_info=req_info)
    assert state.resp_info is not None  # the quote leg broadcasts a respInfo

    quote_stmt = prepare_asn1_attestation_statement(quote_oid, bytes(der_encoder.encode(univ.Sequence())))
    bundle = bytes(der_encoder.encode(prepare_attestation_bundle([quote_stmt])))
    outcome = engine.verify_bundle(bundle, tx)

    assert outcome.accepted
    assert outcome.first_ear == "tpm.ear.jwt"
    assert captured["oid"] == quote_oid
    assert captured["nonce"] == state.nonce
    assert captured["resp_info_json"] == {"pcrSelection": [0, 1, 2, 3, 4], "hashAlgo": 11}
