# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the generic token layer (:mod:`libattest.tokens`).

The load-bearing test here is
:func:`test_jwt_and_cwt_of_the_same_claims_appraise_identically`: a JWT and a CWT
carrying the same claims must decode to the *same* canonical claim set, because
that equivalence is what lets one appraisal path serve both renderings. Everything
else defends a rejection that used to be an acceptance.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt import COSEKey

from libattest.formats.eat_ear.cwt_jwt import jwt_claims_to_cwt_claim_set
from libattest.formats.media_types import EAT_CWT, EAT_JWT, EAT_UCS_CBOR, EAT_UCS_JSON
from libattest.tokens import TOKENS, CwtCodec, JwsCodec, UccsCodec, UjcsCodec, UnknownMediaTypeError
from libattest.tokens.cose import COSE_MAC0_TAG, CWT_TAG

NONCE = b"\x07" * 32
EAT_NONCE_LABEL = 10  # RFC 9711 eat_nonce


@pytest.fixture(name="ec_keys")
def _ec_keys() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Return a P-256 private key and its PEM public half."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem


def _cose_keypair() -> tuple[COSEKey, COSEKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return COSEKey.from_pem(private_pem, kid="ak-1"), COSEKey.from_pem(public_pem, kid="ak-1")


# ── the G1 property: one claims shape regardless of rendering ────────────────────
def test_jwt_and_cwt_of_the_same_claims_appraise_identically(ec_keys) -> None:
    """GIVEN the same claims as a JWT and a CWT THEN both decode to one canonical claim set."""
    private_key, public_pem = ec_keys
    signing_key, verify_key = _cose_keypair()
    claims = {"iss": "https://attester.example", "sub": "device-0007"}

    jws = JwsCodec().encode(jwt_claims_to_cwt_claim_set(claims), signer=private_key, algorithm="ES256")
    jwt_token = TOKENS.decode(jws, EAT_JWT, keys=public_pem)

    cwt = CwtCodec().encode(jwt_claims_to_cwt_claim_set(claims), signer=signing_key)
    cwt_token = TOKENS.decode(cwt, EAT_CWT, keys=verify_key)

    assert jwt_token.claims == cwt_token.claims
    assert jwt_token.verified and cwt_token.verified
    assert jwt_token.claim(1) == "https://attester.example"  # iss, by integer label
    assert cwt_token.claim(2) == "device-0007"  # sub, same label in both


def test_byte_valued_claims_survive_as_bytes(ec_keys) -> None:
    """GIVEN an eat_nonce WHEN carried as a JWT THEN it decodes to raw bytes, not base64url text."""
    private_key, public_pem = ec_keys
    claims = jwt_claims_to_cwt_claim_set({"eat_nonce": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"})

    token = TOKENS.decode(JwsCodec().encode(claims, signer=private_key), EAT_JWT, keys=public_pem)
    assert token.claim(EAT_NONCE_LABEL) == NONCE


def test_json_view_is_a_rendering_not_a_second_source_of_truth(ec_keys) -> None:
    """GIVEN a decoded token THEN as_json_view renders readable names off the canonical labels."""
    private_key, public_pem = ec_keys
    claims = jwt_claims_to_cwt_claim_set({"iss": "https://attester.example"})
    token = TOKENS.decode(JwsCodec().encode(claims, signer=private_key), EAT_JWT, keys=public_pem)

    assert token.as_json_view()["iss"] == "https://attester.example"


# ── algorithm allowlist (replaces the ES256/single-key pinning) ──────────────────
def test_jws_algorithm_outside_the_allowlist_is_rejected(ec_keys) -> None:
    """GIVEN a codec restricted to RS256 WHEN an ES256 token arrives THEN reject before verifying."""
    private_key, public_pem = ec_keys
    jws = JwsCodec().encode(jwt_claims_to_cwt_claim_set({"iss": "x"}), signer=private_key)

    with pytest.raises(ValueError, match="not accepted"):
        JwsCodec(algorithms={"RS256"}).decode(jws, keys=public_pem)


def test_none_algorithm_cannot_be_configured() -> None:
    """GIVEN an attempt to allow alg=none THEN the codec refuses to be built."""
    with pytest.raises(ValueError, match="never acceptable"):
        JwsCodec(algorithms={"none"})


def test_missing_key_is_a_rejection_not_a_crash(ec_keys) -> None:
    """GIVEN a kid with no provisioned key THEN raise ValueError, not KeyError/AttributeError."""
    private_key, _ = ec_keys
    jws = JwsCodec().encode(jwt_claims_to_cwt_claim_set({"iss": "x"}), signer=private_key, headers={"kid": "unknown"})
    with pytest.raises(ValueError, match="no verification key"):
        JwsCodec().decode(jws, keys={"ak-1": b"irrelevant"})


def test_key_resolver_callable_is_supported(ec_keys) -> None:
    """GIVEN a resolver callable THEN the codec selects the key from the header."""
    private_key, public_pem = ec_keys
    jws = JwsCodec().encode(jwt_claims_to_cwt_claim_set({"iss": "x"}), signer=private_key, headers={"kid": "ak-9"})
    seen: list[str] = []

    def resolver(header):
        seen.append(header.get("kid", ""))
        return public_pem

    assert JwsCodec().decode(jws, keys=resolver).verified
    assert seen == ["ak-9"]


# ── COSE structure is decided before any key is used ─────────────────────────────
def test_cose_mac0_is_not_accepted_as_a_signed_cwt() -> None:
    """GIVEN a COSE_Mac0 WHEN decoded as application/eat+cwt THEN reject.

    The pre-existing cose_cwt_to_jwt_view renders a Mac0 as ordinary claims; a
    decoder that cannot tell a signature from a MAC cannot ground an appraisal.
    """
    mac0 = cbor2.dumps(cbor2.CBORTag(COSE_MAC0_TAG, [b"", {}, cbor2.dumps({1: "iss"}), b"tag"]))
    with pytest.raises(ValueError, match="expected a COSE_Sign1"):
        CwtCodec().decode(mac0, keys=b"irrelevant")


def test_bare_claim_map_is_not_accepted_as_a_signed_cwt() -> None:
    """GIVEN an unsigned claim map under the signed media type THEN reject."""
    with pytest.raises(ValueError, match="unsigned claim set"):
        CwtCodec().decode(cbor2.dumps({1: "iss"}), keys=b"irrelevant")


def test_cwt_tag_61_is_unwrapped() -> None:
    """GIVEN a claim set wrapped in CWT tag 61 THEN the tag is transparent to the decoder."""
    tagged = cbor2.dumps(cbor2.CBORTag(CWT_TAG, {1: "iss"}))
    assert UccsCodec().decode(tagged).claim(1) == "iss"


def test_signed_payload_is_refused_under_the_unsigned_media_type() -> None:
    """GIVEN a COSE_Sign1 sent as eat-ucs+cbor THEN reject rather than accept it unverified."""
    signing_key, _ = _cose_keypair()
    signed = CwtCodec().encode({1: "iss"}, signer=signing_key)
    with pytest.raises(ValueError, match="carries a COSE structure"):
        UccsCodec().decode(signed)


# ── unsigned claim sets decode, and say so ───────────────────────────────────────
def test_unsigned_claim_sets_report_verified_false() -> None:
    """GIVEN UJCS and UCCS payloads THEN both decode with verified=False."""
    ujcs = TOKENS.decode(b'{"iss":"https://attester.example"}', EAT_UCS_JSON)
    uccs = TOKENS.decode(cbor2.dumps({1: "https://attester.example"}), EAT_UCS_CBOR)

    assert ujcs.verified is False
    assert uccs.verified is False
    assert ujcs.claims == uccs.claims


def test_ujcs_rejects_a_non_object() -> None:
    """GIVEN a JSON array under eat-ucs+json THEN reject."""
    with pytest.raises(ValueError, match="must be an object"):
        UjcsCodec().decode(b"[1,2,3]")


# ── registry dispatch ────────────────────────────────────────────────────────────
def test_media_type_parameters_are_ignored_for_dispatch(ec_keys) -> None:
    """GIVEN an eat_profile parameter THEN dispatch still finds the codec (RFC 9782)."""
    private_key, public_pem = ec_keys
    jws = JwsCodec().encode(jwt_claims_to_cwt_claim_set({"iss": "x"}), signer=private_key)
    assert TOKENS.decode(jws, f'{EAT_JWT}; eat_profile="1.2.3.4"', keys=public_pem).verified


def test_unknown_media_type_is_distinguishable_from_bad_evidence() -> None:
    """GIVEN an unregistered media type THEN raise UnknownMediaTypeError, not a verdict."""
    with pytest.raises(UnknownMediaTypeError, match="no token codec registered"):
        TOKENS.decode(b"{}", "application/vnd.nobody.knows")


def test_all_four_rfc9782_media_types_are_registered() -> None:
    """GIVEN the default registry THEN the RFC 9782 constants are no longer dead code."""
    assert TOKENS.media_types() == sorted([EAT_CWT, EAT_JWT, EAT_UCS_CBOR, EAT_UCS_JSON])


def test_a_new_format_registers_without_editing_the_library() -> None:
    """GIVEN a codec defined outside libattest THEN registering it is enough to dispatch."""

    class VendorCodec:
        media_types = frozenset({"application/vnd.example+cbor"})

        def decode(self, raw, *, keys=None, aad=None):
            from libattest.tokens.model import Token

            return Token(media_type="application/vnd.example+cbor", claims={1: raw.decode()}, verified=False)

        def encode(self, claims, *, signer=None, aad=None):
            return str(claims[1]).encode()

    from libattest.tokens import TokenRegistry

    registry = TokenRegistry()
    registry.register(VendorCodec())
    assert registry.decode(b"hello", "application/vnd.example+cbor").claim(1) == "hello"
