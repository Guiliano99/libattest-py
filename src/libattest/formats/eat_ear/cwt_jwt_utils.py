#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Signing and sealing helpers for EAT/EAR tokens (JOSE + COSE).

Consolidated home (see docs/plans/eat_ear-consolidation.hardened.md) merging
``cwt_utils`` (ES256 keygen, verified JWT->CWT re-issue, CWT re-sign), ``jose_jws``
(ES256 compact JWS + P-256 JWK), ``jose_hpke`` (JOSE-HPKE-0 integrated JWE), and
``cose_hpke`` (COSE-HPKE-0 seal/open).

The two HPKE ``alg`` constants that collided when these modules were merged into one
namespace are kept distinct: ``ES256_ALG`` ("ES256", the JWS alg) and ``HPKE0_ALG``
("HPKE-0", the JOSE-HPKE-0 alg).
"""

from __future__ import annotations

import base64
import json
from collections.abc import Sequence
from typing import Any, cast

import cbor2
import cwt
import jwt
import jwt as pyjwt  # PyJWT -- aliased so it reads unambiguously next to `cwt`
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hpke as _hpke
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt import COSE, COSEAlgs, COSEHeaders, COSEKey, CWTClaims

from libattest.formats.eat_ear.cwt_jwt import jwt_claims_to_cwt_claim_set

# --------------------------------------------------------------------------
# Key helpers
# --------------------------------------------------------------------------


def generate_es256_keypair(kid: str = "my-signing-key-01"):
    """
    Generate a fresh ES256 (P-256) key pair.

    Returns (signing_key, verify_key, private_pem, public_pem):
    the first two are COSEKeys for cwt.encode/decode, the PEMs are raw
    bytes for PyJWT, which doesn't understand COSEKey objects.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    signing_key = COSEKey.from_pem(private_pem, kid=kid)
    verify_key = COSEKey.from_pem(public_pem, kid=kid)
    return signing_key, verify_key, private_pem, public_pem


# --------------------------------------------------------------------------
# JWT -> CWT conversion
# --------------------------------------------------------------------------


def jwt_claims_to_cwt_claims(jwt_claims: dict) -> dict:
    """
    Map JWT registered claim names onto their CWT equivalents (RFC 8392 S3.1).

    Only "jti" needs real conversion: JWT's jti is a string, CWT's cti
    (claim key 7) is REQUIRED to be a byte string. iss/sub/aud/exp/nbf/iat
    have the same name and type in both, so python-cwt's string-keyed
    claims API accepts them unchanged.
    """
    cwt_claims = dict(jwt_claims)
    if "jti" in cwt_claims:
        jti = cwt_claims.pop("jti")
        cwt_claims["cti"] = jti.encode("utf-8") if isinstance(jti, str) else jti
    return cwt_claims


def jwt_to_cwt_claims(
    jwt_token: str,
    jwt_verify_key=None,
    jwt_algorithms=None,
    audience=None,
) -> dict:
    """
    Decode a JWT and map its claims onto CWT claim names (RFC 8392 S3.1).

    Args:
        jwt_token: the compact-serialized JWT string.
        jwt_verify_key: PEM/key used to verify the incoming JWT's signature.
            If None, the JWT signature is NOT verified -- only do this for
            already-trusted/local tokens.
        jwt_algorithms: list of JWT "alg" values to accept, required by
            PyJWT whenever jwt_verify_key is given (e.g. ["ES256"]).
        audience: expected "aud" value. PyJWT raises InvalidAudienceError
            for any token carrying an "aud" claim unless you either pass
            the audience you expect or explicitly opt out of the check, so
            this is threaded through instead of silently disabling it.

    """
    if jwt_verify_key is not None:
        jwt_claims = pyjwt.decode(
            jwt_token,
            key=jwt_verify_key,
            algorithms=jwt_algorithms,
            audience=audience,
            options={"verify_aud": audience is not None},
        )
    else:
        jwt_claims = pyjwt.decode(
            jwt_token,
            options={"verify_signature": False, "verify_aud": False},
        )
    return jwt_claims_to_cwt_claims(jwt_claims)


def convert_jwt_to_cwt(
    jwt_token: str,
    cwt_signing_key: Any,
    jwt_verify_key: Any = None,
    jwt_algorithms: Sequence[str] | None = None,
    audience: str | Sequence[str] | None = None,
) -> bytes:
    """
    Convert a signed JWT into a freshly-signed CWT.

    A JWT's JWS signature can't be carried over into COSE -- container
    format, canonicalization, and signature encoding all differ -- so this
    always verifies and re-signs: it lifts verified claims into a CWT Claim Set
    and produces a brand-new COSE_Sign1 CWT over the raw CBOR payload.

    Args:
        jwt_token: the compact-serialized JWT string.
        cwt_signing_key: COSE key used to sign the resulting CWT.
        jwt_verify_key: PEM/key required to verify the incoming JWT signature.
        jwt_algorithms: Non-empty list of accepted JWT algorithms, such as
            ``["ES256"]``.
        audience: Required expected ``aud`` value or values for the source JWT.

    """
    if jwt_algorithms is None:
        raise ValueError("jwt_algorithms must contain at least one accepted algorithm")
    return verified_jwt_to_signed_cwt(
        jwt_token,
        cwt_signing_key,
        jwt_verify_key=jwt_verify_key,
        jwt_algorithms=jwt_algorithms,
        audience=audience,
    )


def verified_jwt_to_signed_cwt(
    jwt_token: str,
    cwt_signing_key: Any,
    *,
    jwt_verify_key: Any,
    jwt_algorithms: Sequence[str],
    audience: str | Sequence[str] | None = None,
) -> bytes:
    """Verify a compact JWT and issue a new lossless COSE_Sign1 CWT.

    Arguments:
        jwt_token: Compact JWS/JWT to verify before its claims are used.
        cwt_signing_key: COSE key used to create the new COSE_Sign1 signature.
        jwt_verify_key: Public key or PEM accepted by PyJWT for JWT verification.
        jwt_algorithms: Accepted JWT JWS algorithms, such as ``["ES256"]``.
        audience: Required expected JWT audience or audiences.

    Returns:
        A newly signed COSE_Sign1 CWT whose payload is the raw CBOR CWT Claim
        Set. Private and EAT claims are retained because ``cwt.encode()`` is
        not used.

    Raises:
        ValueError: If no JWT verification key, accepted algorithms, or expected
            audience is given.
        jwt.PyJWTError: If JWT verification fails.

    """
    if jwt_verify_key is None:
        raise ValueError("jwt_verify_key is required when issuing a signed CWT")
    if not jwt_algorithms:
        raise ValueError("jwt_algorithms must contain at least one accepted algorithm")
    if not audience:
        raise ValueError("audience is required when issuing a signed CWT")

    jwt_claims = pyjwt.decode(
        jwt_token,
        key=jwt_verify_key,
        algorithms=list(jwt_algorithms),
        audience=audience,
        options={"require": ["aud"]},
    )
    if not isinstance(jwt_claims, dict):
        raise ValueError("verified JWT claims must be a JSON object")

    payload = cbor2.dumps(jwt_claims_to_cwt_claim_set(jwt_claims))
    signed_cwt = COSE.new().encode_and_sign(
        payload,
        cwt_signing_key,
        protected={COSEHeaders.ALG: cwt_signing_key.alg},
    )
    if not isinstance(signed_cwt, bytes):
        raise ValueError("COSE signing did not produce encoded CWT bytes")
    return signed_cwt


# --------------------------------------------------------------------------
# Re-signing an existing CWT
# --------------------------------------------------------------------------


def resign_cwt(
    cwt_token: bytes,
    old_verify_key: Any,
    new_signing_key: Any,
    refresh_validity: bool = False,
    expires_in: int = 3600,
) -> bytes:
    """Verify an existing CWT, then re-sign the same claims under a different key.

    Supports key rotation / re-issuance.

    Args:
        cwt_token: the CBOR-encoded CWT to re-sign.
        old_verify_key: key that verifies the existing signature.
        new_signing_key: key to sign the reissued CWT with.
        refresh_validity: if True, drop the old exp/nbf/iat so python-cwt
            regenerates them from the current time instead of carrying the
            original validity window forward.
        expires_in: lifetime in seconds to use when refresh_validity=True.

    """
    claims = cwt.decode(cwt_token, old_verify_key)
    if not isinstance(claims, dict):
        raise ValueError("CWT re-signing requires a decoded CWT Claim Set")

    if refresh_validity:
        for claim_id in (CWTClaims.EXP, CWTClaims.NBF, CWTClaims.IAT):
            claims.pop(claim_id, None)
        ctx = cwt.CWT.new(expires_in=expires_in)
        return ctx.encode(cast(Any, claims), new_signing_key)

    return cwt.encode(cast(Any, claims), new_signing_key)


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------


def main():
    """Run the three CWT demos (plain sign+verify, JWT->CWT, re-sign) with printed output."""
    # --- 1. Plain CWT: generate + sign + verify -------------------------
    cwt_key, cwt_verify_key, _, _ = generate_es256_keypair(kid="cwt-key-01")

    claims = {
        "iss": "https://issuer.example",
        "sub": "user-1234",
        "aud": "https://api.example",
        "cti": "cwt-0001",
    }
    token = cwt.encode(claims, cwt_key)
    print(f"1) Signed CWT ({len(token)} bytes, hex):")
    print(token.hex())
    print("   Decoded & verified:", cwt.decode(token, cwt_verify_key))

    # --- 2. Convert a JWT into a CWT -------------------------------------
    _, _, jwt_private_pem, jwt_public_pem = generate_es256_keypair(kid="jwt-key-01")
    jwt_claims = {
        "iss": "https://issuer.example",
        "sub": "user-1234",
        "aud": "https://api.example",
        "jti": "jwt-0001",
    }
    demo_jwt = pyjwt.encode(jwt_claims, jwt_private_pem, algorithm="ES256")
    print("\n2) Demo JWT:")
    print(demo_jwt)

    converted = convert_jwt_to_cwt(
        demo_jwt,
        cwt_signing_key=cwt_key,
        jwt_verify_key=jwt_public_pem,
        jwt_algorithms=["ES256"],
        audience="https://api.example",
    )
    print("   Converted to CWT, decoded & verified:")
    print("  ", cwt.decode(converted, cwt_verify_key))

    # --- 3. Re-sign an existing CWT under a new key ----------------------
    new_cwt_key, new_cwt_verify_key, _, _ = generate_es256_keypair(kid="cwt-key-02")
    resigned = resign_cwt(
        token,
        cwt_verify_key,
        new_cwt_key,
        refresh_validity=True,
        expires_in=7200,
    )
    print("\n3) Re-signed CWT under a new key, decoded & verified:")
    print("  ", cwt.decode(resigned, new_cwt_verify_key))


# ============================================================================
#  ES256 compact JWS + P-256 JWK (former libattest.formats.jose_jws)
# ============================================================================

ES256_ALG = "ES256"

# Shared ES256 algorithm handle for EC P-256 <-> JWK conversion (PyJWT public API).
_ES256 = jwt.get_algorithm_by_name(ES256_ALG)


# ── base64url (unpadded, as JOSE requires) ──────────────────────────────────────
def b64u_decode(s: str) -> bytes:
    """base64url-decode a string, restoring the stripped ``=`` padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_encode(b: bytes) -> str:
    """base64url-encode bytes without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── P-256 JWK <-> cryptography EC keys (delegated to PyJWT) ───────────────────────
def p256_public_to_jwk(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    """Return the public-half P-256 JWK (``kty``/``crv``/``x``/``y``)."""
    return _ES256.to_jwk(public_key, as_dict=True)


def p256_private_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
    """Return the private P-256 JWK (the public JWK plus the ``d`` parameter)."""
    return _ES256.to_jwk(private_key, as_dict=True)


def _p256_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey:
    """Load an EC key from a P-256 JWK via PyJWT, enforcing the P-256 profile.

    PyJWT's ``from_jwk`` itself accepts other curves and raises ``InvalidKeyError``; this
    pins the curve and normalises failures to ``ValueError`` (this module's contract).
    """
    if jwk.get("crv") != "P-256":
        raise ValueError("expected a P-256 EC JWK")
    try:
        return _ES256.from_jwk(jwk)
    except jwt.PyJWTError as exc:
        raise ValueError(f"invalid P-256 EC JWK: {exc}") from exc


def jwk_to_p256_public(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Build a P-256 public key from a JWK dict."""
    key = _p256_key_from_jwk(jwk)
    return key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key


def jwk_to_p256_private(jwk: dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    """Build a P-256 private key from a JWK dict (must carry ``d``)."""
    if "d" not in jwk:
        raise ValueError("private JWK must contain the 'd' parameter")
    key = _p256_key_from_jwk(jwk)
    if not isinstance(key, ec.EllipticCurvePrivateKey):  # 'd' present ⇒ private; defensive
        raise ValueError("expected a private P-256 EC JWK")
    return key


# ── ES256 compact JWS ────────────────────────────────────────────────────────────
def _load_public_key(key: ec.EllipticCurvePublicKey | bytes | str) -> ec.EllipticCurvePublicKey:
    """Accept an EC public key, a PEM (str/bytes), or DER SPKI bytes."""
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key
    data = key.encode("ascii") if isinstance(key, str) else key
    for loader in (serialization.load_pem_public_key, serialization.load_der_public_key):
        try:
            loaded = loader(data)
        except ValueError:
            continue
        if isinstance(loaded, ec.EllipticCurvePublicKey):
            return loaded
        raise ValueError("JWS verification key is not an EC public key")
    raise ValueError("could not load an EC public key from the given PEM/DER bytes")


def sign_es256(payload: dict[str, Any], private_key: ec.EllipticCurvePrivateKey) -> str:
    """Sign *payload* as an ES256 compact JWS and return the token string."""
    # PyJWT already emits the {"alg": "ES256", "typ": "JWT"} header by default.
    return jwt.encode(payload, private_key, algorithm=ES256_ALG)


def verify_es256(token: str, key: ec.EllipticCurvePublicKey | bytes | str) -> dict[str, Any]:
    """Verify an ES256 compact JWS and return its claims.

    :raises ValueError: malformed token or non-ES256 ``alg``.
    :raises cryptography.exceptions.InvalidSignature: the signature does not verify.
    """
    public_key = _load_public_key(key)
    try:
        return jwt.decode(
            token,
            public_key,
            algorithms=[ES256_ALG],
            # Signature + alg stay enforced (verify_signature defaults on; algorithms pins ES256).
            # Every registered-claim check is disabled so claims are returned verbatim, exactly
            # like the old hand-rolled verify — freshness/appraisal is the verifier's job. Without
            # this PyJWT would reject e.g. a cross-machine inner-EAT ``iat`` skew or any ``aud``.
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
                "verify_sub": False,
                "verify_jti": False,
            },
        )
    except jwt.InvalidSignatureError as exc:  # subclass of DecodeError — must precede it
        raise InvalidSignature(str(exc)) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise ValueError(f"unsupported JWS alg; expected {ES256_ALG}") from exc
    except jwt.PyJWTError as exc:  # malformed token, bad header, etc.
        raise ValueError(f"invalid compact JWS: {exc}") from exc


# ============================================================================
#  JOSE-HPKE-0 integrated JWE (former libattest.formats.jose_hpke)
# ============================================================================

# JOSE-HPKE alg for the only suite this profile allows.  In draft-20 ``HPKE-0`` is itself
# an Integrated-Encryption algorithm: the protected header carries ``alg`` only, with NO
# separate ``enc`` parameter (that split was the older -12 model).
HPKE0_ALG = "HPKE-0"

# Bind the private aad-capable single-shot helpers at import time, with a clear error if
# a future cryptography release relocates them (see the module docstring).
try:
    from cryptography.hazmat.primitives.hpke import rust_openssl as _rust_openssl

    _encrypt_with_aad = _rust_openssl.hpke._encrypt_with_aad
    _decrypt_with_aad = _rust_openssl.hpke._decrypt_with_aad
except (ImportError, AttributeError) as exc:  # pragma: no cover - exercised by a guard test
    raise RuntimeError(
        "JOSE-HPKE-0 requires cryptography's aad-capable HPKE helpers "
        "(_encrypt_with_aad/_decrypt_with_aad); this cryptography build does not expose them. "
        "Pin cryptography>=49.0.0 with the OpenSSL HPKE backend."
    ) from exc


_HPKE0_SUITE: _hpke.Suite | None = None


def hpke0_suite() -> _hpke.Suite:
    """Return the (cached) HPKE-0 cipher suite: DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM.

    The suite is an immutable (KEM, KDF, AEAD) descriptor — seal/open create their own
    per-call contexts — so one shared instance is safe and avoids re-allocating it each call.
    """
    global _HPKE0_SUITE
    if _HPKE0_SUITE is None:
        _HPKE0_SUITE = _hpke.Suite(_hpke.KEM.P256, _hpke.KDF.HKDF_SHA256, _hpke.AEAD.AES_128_GCM)
    return _HPKE0_SUITE


def _enc_len(public_key: ec.EllipticCurvePublicKey) -> int:
    """Return the DHKEM ``enc`` length (the uncompressed-point size for this curve)."""
    point = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return len(point)


def _as_private_key(key: ec.EllipticCurvePrivateKey | dict[str, Any]) -> ec.EllipticCurvePrivateKey:
    return key if isinstance(key, ec.EllipticCurvePrivateKey) else jwk_to_p256_private(key)


def _as_public_key(key: ec.EllipticCurvePublicKey | dict[str, Any]) -> ec.EllipticCurvePublicKey:
    return key if isinstance(key, ec.EllipticCurvePublicKey) else jwk_to_p256_public(key)


def open_integrated(
    compact_jwe: str,
    recipient_priv: ec.EllipticCurvePrivateKey | dict[str, Any],
) -> tuple[dict, bytes]:
    """Open an HPKE-0 Integrated compact JWE.

    :param compact_jwe: ``protected.enc..ciphertext.`` (empty IV and Tag).
    :param recipient_priv: a P-256 ``cryptography`` private key or a private JWK dict.
    :returns: ``(protected_header, plaintext)``.
    :raises ValueError: malformed JWE / unsupported alg / non-empty IV or Tag.
    :raises cryptography.exceptions.InvalidTag: AEAD failure (wrong key / tampered ct / bad aad).
    """
    parts = compact_jwe.split(".")
    if len(parts) != 5:
        raise ValueError("compact JWE must have 5 dot-separated parts")
    protected_b64, enc_b64, iv, ct_b64, tag = parts
    if iv or tag:
        raise ValueError("HPKE-0 Integrated Encryption requires empty IV and Tag")

    header = json.loads(b64u_decode(protected_b64))
    # HPKE-0 is itself the Integrated-Encryption alg (draft-20 §5.1); the protected header
    # carries ``alg`` only and no separate ``enc`` parameter.
    if header.get("alg") != HPKE0_ALG:
        raise ValueError(f"unsupported JOSE-HPKE alg: {header.get('alg')!r} (this profile allows only {HPKE0_ALG})")

    # Compact serialization carries no JWE AAD, so the HPKE aad is ASCII(protected header).
    aad = protected_b64.encode("ascii")
    blob = b64u_decode(enc_b64) + b64u_decode(ct_b64)  # cryptography expects enc || ct
    sk = _as_private_key(recipient_priv)
    plaintext = _decrypt_with_aad(hpke0_suite(), blob, sk, b"", aad)
    return header, plaintext


def seal_integrated(
    plaintext: bytes,
    protected_header: dict,
    recipient_pub: ec.EllipticCurvePublicKey | dict[str, Any],
) -> str:
    """Seal *plaintext* as an HPKE-0 Integrated compact JWE (used for tests/round-trip).

    The attester-side equivalent is done in gencmpclient via OpenSSL ``OSSL_HPKE_*``;
    this Python sealer exists for conformance/round-trip testing of the verifier path.
    """
    header = dict(protected_header)
    header.setdefault("alg", HPKE0_ALG)
    protected_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    aad = protected_b64.encode("ascii")

    pkr = _as_public_key(recipient_pub)
    blob = _encrypt_with_aad(hpke0_suite(), plaintext, pkr, b"", aad)
    enc_len = _enc_len(pkr)
    enc, ct = blob[:enc_len], blob[enc_len:]
    # protected '.' enc '.' (empty IV) '.' ciphertext '.' (empty Tag)
    return ".".join([protected_b64, b64u_encode(enc), "", b64u_encode(ct), ""])


# ============================================================================
#  COSE-HPKE-0 seal/open (former libattest.formats.cose_hpke)
# ============================================================================

# AttestationStatement.type OID for COSE-HPKE-encrypted software evidence (draft-ietf-cose-hpke).
# Distinct from the JOSE-HPKE evidence OID (libattest.formats.eareat_hpke.EVIDENCE_ENC_OID,
# 1.3.6.1.4.1.99999.10) so the two wire formats never collide; matches gencmpclient's
# ATG_COSE_HPKE_STMT_TYPE_OID (src/cmpClient.c).
COSE_HPKE_STMT_TYPE_OID = "1.3.6.1.4.1.99999.20"


def _ec_priv_to_cose_key(key: ec.EllipticCurvePrivateKey, kid: str) -> Any:
    """Adapt a ``cryptography`` EC private key to a ``COSEKey`` (via PEM; no direct API)."""
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cast(Any, COSEKey.from_pem(pem, kid=kid))


def _ec_pub_to_cose_key(key: ec.EllipticCurvePublicKey, kid: str) -> Any:
    """Adapt a ``cryptography`` EC public key to a ``COSEKey`` (via PEM; no direct API)."""
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cast(Any, COSEKey.from_pem(pem, kid=kid))


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
    claims = jwt_to_cwt_claims(ear_jwt.decode("ascii"))
    payload = cast(bytes, cbor2.dumps(claims))
    recipient_key = _ec_pub_to_cose_key(recipient_pub_key, kid="cose-hpke-recipient")
    if signing_key is not None:
        signer_key = _ec_priv_to_cose_key(signing_key, kid="cose-hpke-signer")
        payload = cast(
            bytes,
            COSE.new().encode_and_sign(
                payload,
                signer_key,
                protected={COSEHeaders.ALG: signer_key.alg},
            ),
        )
    return cast(
        bytes,
        COSE.new().encode_and_encrypt(
            payload,
            recipient_key,
            protected={COSEHeaders.ALG: COSEAlgs.HPKE_0},
        ),
    )


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
    payload = cast(bytes, COSE.new().decode(encrypted, recipient_key))
    if verify_key is not None:
        signer_key = _ec_pub_to_cose_key(verify_key, kid="cose-hpke-signer")
        payload = cast(bytes, COSE.new().decode(payload, signer_key))
    return cbor2.loads(payload)


__all__ = [
    # keygen + verified CWT signing / re-issue (former cwt_utils)
    "generate_es256_keypair",
    "jwt_claims_to_cwt_claims",
    "jwt_to_cwt_claims",
    "convert_jwt_to_cwt",
    "verified_jwt_to_signed_cwt",
    "resign_cwt",
    # ES256 compact JWS + P-256 JWK (former jose_jws)
    "ES256_ALG",
    "InvalidSignature",
    "b64u_decode",
    "b64u_encode",
    "jwk_to_p256_private",
    "jwk_to_p256_public",
    "p256_private_to_jwk",
    "p256_public_to_jwk",
    "sign_es256",
    "verify_es256",
    # JOSE-HPKE-0 (former jose_hpke)
    "HPKE0_ALG",
    "hpke0_suite",
    "open_integrated",
    "seal_integrated",
    # COSE-HPKE-0 (former cose_hpke)
    "COSE_HPKE_STMT_TYPE_OID",
    "open_cose_hpke_evidence",
    "seal_cose_hpke_evidence",
]


if __name__ == "__main__":
    main()
