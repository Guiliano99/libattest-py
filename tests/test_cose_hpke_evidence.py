# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""COSE-HPKE evidence sealing over a static EAR/EAT JWT (draft-ietf-cose-hpke).

Usage example + verification for :func:`libattest.formats.cwt_jwt_utils.seal_cose_hpke_evidence`
/ :func:`~libattest.formats.cwt_jwt_utils.open_cose_hpke_evidence`. Unlike
``test_eareat_hpke_flow.py`` (which generates a fresh EAT-JWS per test via ``jose_jws``),
STATIC_EAR_JWT below is a fixed, pre-generated JWT -- standing in for a real ``atgcli``
token without needing the Go CLI -- so the fixture and expected output never change
between runs. Each test creates fresh signer and recipient keys; the signer
creates the nested CWT signature and the recipient is the verifier's HPKE key.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cwt.exceptions import DecodeError, VerifyError

from libattest.attester import evidence_bridge
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.eat_ear.cwt_jwt_utils import open_cose_hpke_evidence, seal_cose_hpke_evidence

STATIC_EAR_JWT = (
    b"eyJhbGciOiJFUzI1NiIsImtpZCI6ImF0dC1zdGF0aWMtMDEiLCJ0eXAiOiJKV1QifQ."
    b"eyJpc3MiOiJodHRwczovL2F0dGVzdGVyLmV4YW1wbGUiLCJzdWIiOiJkZXZpY2UtMDAwNyIsImVhdF9ub25jZSI6"
    b"IkFRSURCQVVHQndnSkNnc01EUTRQRUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEEiLCJzdWJtb2RzIjp7IkFUR19QTFVH"
    b"SU4iOnsiZWFyLnN0YXR1cyI6ImFmZmlybWluZyJ9fX0."
    b"1vLNg-ork7-GLxalJivPBupCczDhWtpU0_FFY76G9M-6nXeEr7RV4AY1wwggSmcMH3Dfpde0ZTzKpm-CBwxa9A"
)


def test_evidence_bridge_preserves_cose_hpke_public_api() -> None:
    """GIVEN moved COSE helpers WHEN imported from the bridge THEN non-OID aliases still work."""
    assert not hasattr(evidence_bridge, "COSE_HPKE_STMT_TYPE_OID")
    assert evidence_bridge.open_cose_hpke_evidence is cwt_jwt_utils.open_cose_hpke_evidence
    assert evidence_bridge.seal_cose_hpke_evidence is cwt_jwt_utils.seal_cose_hpke_evidence


def _recipient_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Create a fresh P-256 recipient key pair for an HPKE round trip."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def test_encrypt_only_roundtrip() -> None:
    """signing_key=None: RFC 8392 Appendix A.5 encrypted CWT, no signature layer."""
    recipient_priv, recipient_pub = _recipient_keypair()

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub)
    claims = open_cose_hpke_evidence(sealed, recipient_priv)

    assert claims["sub"] == "device-0007"
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"


def test_sign_then_encrypt_roundtrip() -> None:
    """signing_key set: nested COSE_Sign1-in-COSE_Encrypt0; verify_key checks the signature.

    Also pins that eat_nonce survives signing byte-for-byte: the ``cwt.encode``
    convenience API would silently drop it (not a registered CWT claim), so
    ``seal_cose_hpke_evidence`` signs the raw CBOR claims map as an opaque payload
    instead (see its docstring).
    """
    recipient_priv, recipient_pub = _recipient_keypair()
    signer_priv = ec.generate_private_key(ec.SECP256R1())
    signer_pub = signer_priv.public_key()

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=signer_priv)
    claims = open_cose_hpke_evidence(sealed, recipient_priv, verify_key=signer_pub)

    assert claims["sub"] == "device-0007"
    assert claims["submods"]["ATG_PLUGIN"]["ear.status"] == "affirming"
    assert claims["eat_nonce"] == "AQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODxA"


def test_sign_then_encrypt_wrong_verify_key_rejected() -> None:
    """Reject a signed payload when the inner COSE verification key is wrong."""
    recipient_priv, recipient_pub = _recipient_keypair()
    signer_priv = ec.generate_private_key(ec.SECP256R1())
    wrong_pub = ec.generate_private_key(ec.SECP256R1()).public_key()

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=signer_priv)
    with pytest.raises(VerifyError):
        open_cose_hpke_evidence(sealed, recipient_priv, verify_key=wrong_pub)


def test_encrypt_only_wrong_recipient_key_rejected() -> None:
    """Reject encrypted evidence when opened with the wrong recipient key."""
    _recipient_priv, recipient_pub = _recipient_keypair()
    wrong_priv = ec.generate_private_key(ec.SECP256R1())

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub)
    with pytest.raises(DecodeError):
        open_cose_hpke_evidence(sealed, wrong_priv)


def test_sign_with_non_p256_key_uses_its_own_alg() -> None:
    """Signer alg is derived from the key (ES384 here), not hardcoded to ES256.

    The recipient stays P-256 (HPKE-0's KEM); only the inner COSE_Sign1 alg varies.
    """
    recipient_priv, recipient_pub = _recipient_keypair()
    p384_signer = ec.generate_private_key(ec.SECP384R1())

    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_pub, signing_key=p384_signer)
    claims = open_cose_hpke_evidence(sealed, recipient_priv, verify_key=p384_signer.public_key())
    assert claims["sub"] == "device-0007"


def test_non_p256_recipient_rejected() -> None:
    """HPKE-0's KEM is DHKEM(P-256): a non-P-256 recipient must fail clearly, not deep in pyhpke."""
    wrong_curve_pub = ec.generate_private_key(ec.SECP384R1()).public_key()
    with pytest.raises(ValueError, match="P-256"):
        seal_cose_hpke_evidence(STATIC_EAR_JWT, wrong_curve_pub)
