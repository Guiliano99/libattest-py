# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""COSE-HPKE appraisal of a real xclaim CWT (RFC 9711 int labels, signed COSE_Sign1 under tag 61).

The EarEatXclaimHpkeDemo attester builds its evidence with the xclaim CLI: a CWT
``tag61(tag18([h'A10126', {}, payload, sig]))`` whose payload is the claims map
``{10: <nonce bstr>, 1: "acme-attester", 6: <iat>, -70000: "secure"}``.  A C client then seals
it as ``COSE_Encrypt0`` HPKE-0 (alg 35, no kid) inside a CMW ``cbor`` record.  These tests pin
the verifier side (:class:`CoseEatHpkeVerifier` with ``label_profile="cwt-int"``) against the
**real xclaim output** committed below, plus the unit behaviour of the pieces that changed:
tag-61 handling in ``open_cose_hpke_evidence`` and the label-profile / byte-string-nonce
handling in ``check_nonce_and_claim``.

HPKE base mode has no sender authentication, so the inner ``COSE_Sign1`` is the only integrity
gate; the unsigned-claims-map cases below prove it cannot be skipped.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey
from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der
from libattest.formats.cmw import encode_cmw_json_record
from libattest.formats.csrattest import prepare_attestation_bundle, prepare_attestation_statement
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import CMW_MEDIA_COSE
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier
from libattest.verifier.eat_appraisal import check_nonce_and_claim, eat_nonce_bytes

# ── golden vectors: real xclaim output (generated 2026-10-02, xclaim @2335757 on the OpenSSL fork) ──
# Reproduce (the signer key is throw-away and was NOT kept; only its public half is committed):
#   openssl ecparam -name prime256v1 -genkey -noout -out signer.pem
#   openssl ec -in signer.pem -pubout -out signer_pub.pem
#   xclaim -claim nonce:000102030405060708090a0b0c0d0e0f -claim iss:acme-attester \
#          -claim iat:1790676506 -claim -70000:<secure|insecure> \
#          -out_form CBOR -out_prot sign -out_sign_key signer.pem -out tok.cwt
# xclaim exits 0 even on errors: the output must start with d8 3d d2 (tag 61, tag 18).
XCLAIM_NONCE = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
XCLAIM_IAT = 1790676506
XCLAIM_SIGNER_PUBLIC_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGR3AaHs8zsjcVnGJX93Sm4LWw+TZ
msZe7ArdKkMkFi2xs8uAGjfZhsl7hcorB8JrbaTC80kVHjjRF//eQpwvvg==
-----END PUBLIC KEY-----
"""
XCLAIM_TOKEN_SECURE = bytes.fromhex(
    "d83dd28443a10126a05834a40a50000102030405060708090a0b0c0d0e0f016d61636d652d6174746573746572"
    "061a6abb8e1a3a0001116f66736563757265584033686c844339487f27c3af0dba47e4e643912ffc3d533183ea"
    "6cbf8e2a1f38e1df9231ec52b204c18107c913d02fa7e1ae6b61cc24696a4017644cc5d09a7208"
)
XCLAIM_TOKEN_INSECURE = bytes.fromhex(
    "d83dd28443a10126a05836a40a50000102030405060708090a0b0c0d0e0f016d61636d652d6174746573746572"
    "061a6abb8e1a3a0001116f68696e73656375726558405bf36b37b1419075a5e205a7cc9d4a70a9f1a75b9f5bf5"
    "e7c180efd04f5d9710ad2ba20460da9e7e96595e2080bf633cc6523b63aca62b205ff9080ff671aabd"
)

XCLAIM_STMT_OID = "1.3.6.1.4.1.99999.21"
OTHER_NONCE = b"\xa5" * 16


# ── helpers ───────────────────────────────────────────────────────────────────────────────────────
def _pem_pub(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def _seal(plaintext: bytes, recipient: ec.EllipticCurvePrivateKey) -> bytes:
    """COSE-HPKE-0 seal *plaintext* to *recipient*: tag16[h'A1011823', {-4: enc}, ct], no kid."""
    return COSE.new().encode_and_encrypt(
        plaintext,
        COSEKey.from_pem(_pem_pub(recipient.public_key())),
        protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
    )


def _bundle(cose: bytes) -> bytes:
    """Wrap *cose* the way the attester does: CMW cbor record -> AttestationStatement -> bundle DER."""
    cmw_der = encode_cmw_json_record(CMW_MEDIA_COSE, cose, cbor=True)
    stmt = prepare_attestation_statement(univ.ObjectIdentifier(XCLAIM_STMT_OID), cmw_der)
    return encode_to_der(prepare_attestation_bundle([stmt]))


def _strip_cwt_tag(token: bytes) -> bytes:
    """Return the bare tag-18 COSE_Sign1 inside xclaim's tag-61 token."""
    return cbor2.dumps(cbor2.loads(token).value)


def _sign_claims(claims: dict, signer: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign an arbitrary claims map as a bare tag-18 COSE_Sign1 (for shapes xclaim cannot emit)."""
    pem = signer.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    key = COSEKey.from_pem(pem)
    return COSE.new().encode_and_sign(cbor2.dumps(claims), key, protected={COSEHeaders.ALG: key.alg})


@pytest.fixture
def recipient() -> ec.EllipticCurvePrivateKey:
    """Return a fresh P-256 HPKE recipient key (the verifier's)."""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def verifier(recipient: ec.EllipticCurvePrivateKey) -> CoseEatHpkeVerifier:
    """Return the xclaim-profile verifier: pinned to the xclaim signer key, CWT int labels."""
    return CoseEatHpkeVerifier(
        attestation_public_key=XCLAIM_SIGNER_PUBLIC_PEM,
        hpke_recipient_key=recipient,
        label_profile="cwt-int",
    )


# ── the golden vectors themselves ─────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("token", "appraisal_value"), [(XCLAIM_TOKEN_SECURE, "secure"), (XCLAIM_TOKEN_INSECURE, "insecure")]
)
def test_golden_token_shape_and_signature(token: bytes, appraisal_value: str) -> None:
    """GIVEN real xclaim bytes THEN tag61(tag18[{1:-7},{},bstr,sig]) verifies once the tag-61 is stripped.

    Also pins *why* the verifier must strip it: python-cwt refuses the tag-61 form outright.
    """
    assert token[:3] == bytes.fromhex("d83dd2")
    item = cbor2.loads(token)
    assert (item.tag, item.value.tag) == (61, 18)
    protected, unprotected, _payload, _signature = item.value.value
    assert protected == bytes.fromhex("a10126")  # {1: -7} = ES256
    assert unprotected == {}

    signer = COSEKey.from_pem(XCLAIM_SIGNER_PUBLIC_PEM)
    claims = cbor2.loads(COSE.new().decode(_strip_cwt_tag(token), signer))
    assert claims == {10: XCLAIM_NONCE, 1: "acme-attester", 6: XCLAIM_IAT, -70000: appraisal_value}
    with pytest.raises(ValueError, match="tag"):
        COSE.new().decode(token, signer)


def test_sealed_encrypt0_is_kidless_hpke0() -> None:
    """GIVEN python-cwt's sealing THEN the Encrypt0 matches the C client's layout: {1:35}, {-4: enc}, no kid."""
    sealed = cbor2.loads(_seal(XCLAIM_TOKEN_SECURE, ec.generate_private_key(ec.SECP256R1())))
    protected, unprotected, _ciphertext = sealed.value
    assert sealed.tag == 16
    assert cbor2.loads(protected) == {1: 35}
    assert set(unprotected) == {-4}  # ek only: no kid (label 4) for the verifier to filter on


# ── end-to-end through the verifier ───────────────────────────────────────────────────────────────
def test_affirming_end_to_end_via_bundle(verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN the real xclaim CWT sealed kid-less THEN verify_bundle_der affirms and issues an EAR over the nonce."""
    bundle = _bundle(_seal(XCLAIM_TOKEN_SECURE, recipient))

    result = verifier.verify_bundle_der(bundle, XCLAIM_NONCE)

    assert result.accepted, result.errors
    ear = cwt_jwt_utils.verify_es256(result.payload, verifier.ear_verification_pem())
    assert ear["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"
    assert ear["eat_nonce"] == cwt_jwt_utils.b64u_encode(XCLAIM_NONCE)


def test_affirming_for_bare_tag18_input(verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN tag 61 stripped by the sender THEN the bare tag-18 COSE_Sign1 is accepted too."""
    bundle = _bundle(_seal(_strip_cwt_tag(XCLAIM_TOKEN_SECURE), recipient))

    assert verifier.verify_bundle_der(bundle, XCLAIM_NONCE).accepted


def test_nonce_mismatch(verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN evidence bound to XCLAIM_NONCE WHEN appraised against another RA nonce THEN reject (replay)."""
    result = verifier.verify_bundle_der(_bundle(_seal(XCLAIM_TOKEN_SECURE, recipient)), OTHER_NONCE)

    assert not result.accepted
    assert "nonce mismatch" in str(result.errors)


def test_claim_mismatch(verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN a validly signed CWT with appraisal claim 'insecure' THEN reject on the claim, not the nonce."""
    result = verifier.verify_bundle_der(_bundle(_seal(XCLAIM_TOKEN_INSECURE, recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "appraisal failed: claim -70000='insecure'" in str(result.errors)


def test_wrong_signer_key(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN a verifier pinned to a different attester key THEN the inner COSE_Sign1 check rejects."""
    other = CoseEatHpkeVerifier(
        attestation_public_key=ec.generate_private_key(ec.SECP256R1()).public_key(),
        hpke_recipient_key=recipient,
        label_profile="cwt-int",
    )

    result = other.verify_bundle_der(_bundle(_seal(XCLAIM_TOKEN_SECURE, recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "Failed to verify" in str(result.errors)  # the signature check, not decrypt/decode


def test_tampered_ciphertext(verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN one flipped bit in the AEAD ciphertext/tag THEN reject."""
    cose = bytearray(_seal(XCLAIM_TOKEN_SECURE, recipient))
    cose[-1] ^= 0x01

    result = verifier.verify_bundle_der(_bundle(bytes(cose)), XCLAIM_NONCE)

    assert not result.accepted
    assert "decrypt/verify failed" in str(result.errors)


@pytest.mark.parametrize("wrapped_in_cwt_tag", [False, True])
def test_unsigned_claims_map_is_rejected(
    verifier: CoseEatHpkeVerifier, recipient: ec.EllipticCurvePrivateKey, *, wrapped_in_cwt_tag: bool
) -> None:
    """GIVEN the exact xclaim claims, unsigned, sealed to the right key THEN reject: HPKE alone authenticates no one."""
    claims = cbor2.loads(
        COSE.new().decode(_strip_cwt_tag(XCLAIM_TOKEN_SECURE), COSEKey.from_pem(XCLAIM_SIGNER_PUBLIC_PEM))
    )
    plaintext = cbor2.dumps(cbor2.CBORTag(61, claims) if wrapped_in_cwt_tag else claims)

    result = verifier.verify_bundle_der(_bundle(_seal(plaintext, recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "not a COSE_Sign1" in str(result.errors)


def test_mixed_label_claims_are_rejected(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN a validly signed claims map carrying both string and int labels THEN reject (no smuggling)."""
    signer = ec.generate_private_key(ec.SECP256R1())
    verifier = CoseEatHpkeVerifier(
        attestation_public_key=signer.public_key(), hpke_recipient_key=recipient, label_profile="cwt-int"
    )
    claims = {
        10: XCLAIM_NONCE,
        -70000: "secure",
        "eat_nonce": cwt_jwt_utils.b64u_encode(XCLAIM_NONCE),
        "mock_claim": "secure",
    }

    result = verifier.verify_bundle_der(_bundle(_seal(_sign_claims(claims, signer), recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "mixed claim labels" in str(result.errors)


def test_default_profile_does_not_accept_int_labels(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN a jwt-string (default) verifier and an int-label token THEN reject: profiles never cross-accept."""
    default = CoseEatHpkeVerifier(attestation_public_key=XCLAIM_SIGNER_PUBLIC_PEM, hpke_recipient_key=recipient)

    result = default.verify_bundle_der(_bundle(_seal(XCLAIM_TOKEN_SECURE, recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "nonce mismatch" in str(result.errors)


def test_appraisal_label_is_forwarded(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN appraisal_label=-70001 THEN the -70000 claim is not what gets appraised."""
    relabelled = CoseEatHpkeVerifier(
        attestation_public_key=XCLAIM_SIGNER_PUBLIC_PEM,
        hpke_recipient_key=recipient,
        label_profile="cwt-int",
        appraisal_label=-70001,
    )

    result = relabelled.verify_bundle_der(_bundle(_seal(XCLAIM_TOKEN_SECURE, recipient)), XCLAIM_NONCE)

    assert not result.accepted
    assert "appraisal failed: claim -70001=''" in str(result.errors)


def test_unknown_label_profile_rejected_at_construction() -> None:
    """GIVEN a misspelt profile THEN fail at construction, not at the first appraisal."""
    with pytest.raises(ValueError, match="label_profile"):
        CoseEatHpkeVerifier(attestation_public_key=XCLAIM_SIGNER_PUBLIC_PEM, label_profile="cwt")


# ── open_cose_hpke_evidence: what may sit inside the Encrypt0 ─────────────────────────────────────
def test_open_strips_cwt_tag_and_verifies(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN tag61(tag18) THEN open_cose_hpke_evidence returns the verified int-labelled claims map."""
    sealed = _seal(XCLAIM_TOKEN_SECURE, recipient)
    verify_key = serialization.load_pem_public_key(XCLAIM_SIGNER_PUBLIC_PEM)

    claims = cwt_jwt_utils.open_cose_hpke_evidence(sealed, recipient, verify_key=verify_key)

    assert claims == {10: XCLAIM_NONCE, 1: "acme-attester", 6: XCLAIM_IAT, -70000: "secure"}


@pytest.mark.parametrize(
    "plaintext",
    [
        pytest.param(cbor2.dumps({10: XCLAIM_NONCE, -70000: "secure"}), id="unsigned-map"),
        pytest.param(cbor2.dumps(cbor2.CBORTag(61, {10: XCLAIM_NONCE})), id="tag61-over-map"),
        pytest.param(
            cbor2.dumps(cbor2.CBORTag(61, cbor2.CBORTag(61, cbor2.loads(XCLAIM_TOKEN_SECURE).value))), id="double-tag61"
        ),
        pytest.param(cbor2.dumps(cbor2.CBORTag(16, [b"", {}, b""])), id="tag16-encrypt0"),
        pytest.param(cbor2.dumps([b"", {}, b"", b""]), id="untagged-sign1"),
        pytest.param(b"\xff", id="not-cbor"),
        pytest.param(b"", id="empty"),
    ],
)
def test_open_with_verify_key_requires_a_sign1(plaintext: bytes, recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN verify_key and a plaintext that is not (tag 61 over) tag-18 COSE_Sign1 THEN ValueError."""
    verify_key = serialization.load_pem_public_key(XCLAIM_SIGNER_PUBLIC_PEM)

    with pytest.raises(ValueError, match="COSE_Sign1|CBOR"):
        cwt_jwt_utils.open_cose_hpke_evidence(_seal(plaintext, recipient), recipient, verify_key=verify_key)


def test_open_encrypt_only_path_is_unchanged(recipient: ec.EllipticCurvePrivateKey) -> None:
    """GIVEN no verify_key THEN an unsigned claims map is still returned as before (legacy encrypt-only form)."""
    claims = {"eat_nonce": "AAAA", "mock_claim": "secure"}

    assert cwt_jwt_utils.open_cose_hpke_evidence(_seal(cbor2.dumps(claims), recipient), recipient) == claims


# ── check_nonce_and_claim / eat_nonce_bytes ───────────────────────────────────────────────────────
def test_bstr_nonce_matches_raw_and_is_not_base64_decoded() -> None:
    """GIVEN a byte-string nonce THEN it is compared raw: matching bytes pass, their base64url text does not."""
    cwt_claims = {10: XCLAIM_NONCE, -70000: "secure"}
    assert check_nonce_and_claim(cwt_claims, XCLAIM_NONCE, "secure", label_profile="cwt-int")[0] == "affirming"

    b64_text_as_bstr = {10: cwt_jwt_utils.b64u_encode(XCLAIM_NONCE).encode(), -70000: "secure"}
    status, reason = check_nonce_and_claim(b64_text_as_bstr, XCLAIM_NONCE, "secure", label_profile="cwt-int")
    assert (status, "nonce mismatch" in reason) == ("contraindicated", True)


def test_str_nonce_still_base64url_decoded_with_padding_tolerance() -> None:
    """GIVEN the legacy jwt-string profile THEN a base64url nonce (padded or not) matches; behaviour unchanged."""
    unpadded = cwt_jwt_utils.b64u_encode(b"\x01\x02\x03\x04\x05")
    for text in (unpadded, unpadded + "=" * (-len(unpadded) % 4)):
        claims = {"eat_nonce": text, "mock_claim": "secure"}
        assert check_nonce_and_claim(claims, b"\x01\x02\x03\x04\x05", "secure")[0] == "affirming"
    assert eat_nonce_bytes(unpadded) == b"\x01\x02\x03\x04\x05"
    assert eat_nonce_bytes("!!!") == b""  # malformed -> b"" (fails the comparison), as before
    assert eat_nonce_bytes(b"\x00\x01") == b"\x00\x01"  # a bstr used to raise TypeError -> silently b""


@pytest.mark.parametrize("bad_nonce", [None, 10, ["a"], [XCLAIM_NONCE], {"n": 1}, True])
def test_non_bytes_non_str_nonce_is_a_mismatch(bad_nonce: object) -> None:
    """GIVEN a nonce of another type (incl. RFC 9711's array-of-bstr form, unsupported) THEN mismatch."""
    status, reason = check_nonce_and_claim(
        {10: bad_nonce, -70000: "secure"}, XCLAIM_NONCE, "secure", label_profile="cwt-int"
    )

    assert (status, "nonce mismatch" in reason) == ("contraindicated", True)


@pytest.mark.parametrize(
    ("claims", "profile"),
    [
        pytest.param(
            {10: cwt_jwt_utils.b64u_encode(XCLAIM_NONCE), -70000: "secure"}, "cwt-int", id="cwt-int-str-nonce"
        ),
        pytest.param({"eat_nonce": XCLAIM_NONCE, "mock_claim": "secure"}, "jwt-string", id="jwt-string-bstr-nonce"),
    ],
)
def test_nonce_type_follows_the_label_profile(claims: dict, profile: str) -> None:
    """GIVEN the right nonce value in the other profile's type THEN mismatch: cwt-int needs a bstr, jwt-string a str."""
    status, reason = check_nonce_and_claim(claims, XCLAIM_NONCE, "secure", label_profile=profile)

    assert (status, "nonce mismatch" in reason) == ("contraindicated", True)


@pytest.mark.parametrize(
    ("claims", "reason_part"),
    [
        pytest.param({10: XCLAIM_NONCE, -70000: "secure", "eat_nonce": "x"}, "mixed", id="eat_nonce+10"),
        pytest.param({10: XCLAIM_NONCE, -70000: "secure", "mock_claim": "secure"}, "mixed", id="mock_claim+int-label"),
        pytest.param({"eat_nonce": "x", "mock_claim": "secure"}, "mixed", id="string-labels-only"),
        pytest.param({"iss": "acme-attester", 6: 1}, "neither", id="no-profile-labels"),
        pytest.param({}, "neither", id="empty"),
    ],
)
def test_cwt_int_profile_rejects_mixed_or_missing_labels(claims: dict, reason_part: str) -> None:
    """GIVEN cwt-int WHEN the claims carry string labels, or no profile label at all THEN contraindicated."""
    status, reason = check_nonce_and_claim(claims, XCLAIM_NONCE, "secure", label_profile="cwt-int")

    assert status == "contraindicated"
    assert reason_part in reason


def test_cwt_int_profile_custom_appraisal_label() -> None:
    """GIVEN appraisal_label=-70001 THEN that label is appraised (and -70000 is ignored)."""
    claims = {10: XCLAIM_NONCE, -70001: "secure", -70000: "insecure"}

    assert (
        check_nonce_and_claim(claims, XCLAIM_NONCE, "secure", label_profile="cwt-int", appraisal_label=-70001)[0]
        == "affirming"
    )
    assert check_nonce_and_claim(claims, XCLAIM_NONCE, "secure", label_profile="cwt-int")[0] == "contraindicated"


def test_jwt_string_profile_ignores_int_labels() -> None:
    """GIVEN the default profile THEN int-label claims never satisfy it (no cross-acceptance)."""
    status, reason = check_nonce_and_claim({10: XCLAIM_NONCE, -70000: "secure"}, XCLAIM_NONCE, "secure")

    assert (status, "nonce mismatch" in reason) == ("contraindicated", True)


def test_unknown_label_profile_raises() -> None:
    """GIVEN a misspelt profile THEN ValueError (never a silent fall back to jwt-string)."""
    with pytest.raises(ValueError, match="label_profile"):
        check_nonce_and_claim({}, XCLAIM_NONCE, "secure", label_profile="cwt")
