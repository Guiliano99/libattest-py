# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""COSE-HPKE-0 seal/open crypto core (draft-ietf-cose-hpke), TPM-free.

The CBOR/COSE analog of :mod:`libattest.formats.jose_hpke`: a standalone
``formats`` module with **no TPM dependency**, so it imports on the software
attester/verifier images (which do not install ``tpm2_pytss``) exactly like the
JOSE-HPKE core does.  Built on ``python-cwt``'s COSE engine (which drives
``pyhpke`` for the HPKE-0 suite) plus ``cbor2``.

HPKE-0 profile: integrated single-recipient COSE-HPKE with
DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM (``COSEAlgs.HPKE_0``), the CBOR
counterpart of the JOSE ``HPKE-0`` suite.

:func:`seal_cose_hpke_evidence` / :func:`open_cose_hpke_evidence` were extracted
from :mod:`libattest.attester.evidence_bridge` (which re-exports them for
backward compatibility) so the software EAR/EAT COSE demo can reach the crypto
core without dragging in the TPM client.
"""

from __future__ import annotations

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey

from libattest.formats import cwt_utils

# AttestationStatement.type OID for COSE-HPKE-encrypted software evidence (draft-ietf-cose-hpke).
# Distinct from the JOSE-HPKE evidence OID (libattest.formats.eareat_hpke.EVIDENCE_ENC_OID,
# 1.3.6.1.4.1.99999.10) so the two wire formats never collide; matches gencmpclient's
# ATG_COSE_HPKE_STMT_TYPE_OID (src/cmpClient.c).
COSE_HPKE_STMT_TYPE_OID = "1.3.6.1.4.1.99999.20"


def _ec_priv_to_cose_key(key: ec.EllipticCurvePrivateKey, kid: str) -> COSEKey:
    """Adapt a ``cryptography`` EC private key to a ``COSEKey`` (via PEM; no direct API)."""
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return COSEKey.from_pem(pem, kid=kid)


def _ec_pub_to_cose_key(key: ec.EllipticCurvePublicKey, kid: str) -> COSEKey:
    """Adapt a ``cryptography`` EC public key to a ``COSEKey`` (via PEM; no direct API)."""
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return COSEKey.from_pem(pem, kid=kid)


def seal_cose_hpke_evidence(
    ear_jwt: bytes,
    recipient_pub_key: ec.EllipticCurvePublicKey,
    signing_key: ec.EllipticCurvePrivateKey | None = None,
) -> bytes:
    """COSE-HPKE-0 encrypt an EAT/EAR JWT for the verifier (draft-ietf-cose-hpke).

    The JWT is decoded (its JWS signature is *not* verified -- the static/local token is
    already trusted), its claims mapped to CWT claim names where they differ (``jti``->
    ``cti``, RFC 8392 S3.1) and CBOR-encoded, then sealed with integrated COSE-HPKE-0
    (DHKEM(P-256)+HKDF-SHA256+AES-128-GCM) to *recipient_pub_key*. If *signing_key* is
    given, the claims are first wrapped in a ``COSE_Sign1`` (nested sign-then-encrypt),
    signed under the key's own EC alg; if ``None``, the claims are encrypted directly
    (RFC 8392 Appendix A.5 encrypted CWT, no signature).

    Signing goes through :meth:`~cwt.COSE.encode_and_sign` over the raw CBOR claims (not
    the ``cwt.encode`` convenience wrapper): ``cwt.encode`` silently drops any claim
    outside its built-in registry and auto-stamps exp/nbf/iat, which would lose
    ``eat_nonce`` -- the freshness binding this evidence exists to protect. Signing the
    opaque claims bytes preserves every claim.

    Returns the bare ``COSE_Encrypt0`` bytes (no CMW/OID/bundle wrapping).

    :raises ValueError: if *recipient_pub_key* is not an EC P-256 key (HPKE-0's KEM).
    """
    if not isinstance(recipient_pub_key.curve, ec.SECP256R1):
        raise ValueError("COSE-HPKE-0 requires an EC P-256 recipient key")
    claims = cwt_utils.jwt_to_cwt_claims(ear_jwt.decode("ascii"))
    payload = cbor2.dumps(claims)
    recipient_key = _ec_pub_to_cose_key(recipient_pub_key, kid="cose-hpke-recipient")
    if signing_key is not None:
        signer_key = _ec_priv_to_cose_key(signing_key, kid="cose-hpke-signer")
        payload = COSE.new().encode_and_sign(payload, signer_key, protected={COSEHeaders.ALG: signer_key.alg})
    return COSE.new().encode_and_encrypt(payload, recipient_key, protected={COSEHeaders.ALG: COSEAlgs.HPKE_0})


def open_cose_hpke_evidence(
    encrypted: bytes,
    recipient_priv_key: ec.EllipticCurvePrivateKey,
    verify_key: ec.EllipticCurvePublicKey | None = None,
) -> dict:
    """Open a :func:`seal_cose_hpke_evidence` result and return the CWT claims map.

    *verify_key* must match whether *encrypted* was sealed with a *signing_key*: pass it
    to verify the inner ``COSE_Sign1``, or omit it for the encrypt-only (unsigned) form.
    """
    recipient_key = _ec_priv_to_cose_key(recipient_priv_key, kid="cose-hpke-recipient")
    payload = COSE.new().decode(encrypted, recipient_key)
    if verify_key is not None:
        signer_key = _ec_pub_to_cose_key(verify_key, kid="cose-hpke-signer")
        payload = COSE.new().decode(payload, signer_key)
    return cbor2.loads(payload)


__all__ = [
    "COSE_HPKE_STMT_TYPE_OID",
    "open_cose_hpke_evidence",
    "seal_cose_hpke_evidence",
]
