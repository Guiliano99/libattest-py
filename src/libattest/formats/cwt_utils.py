#!/usr/bin/env python3
"""Generate/sign a CWT, convert a JWT into a CWT, and re-sign an existing CWT.

Uses python-cwt (+ PyJWT for reading the JWT side).

Install dependencies:
    pip install cwt cryptography pyjwt

Run:
    python generate_cwt.py
"""

import cwt
import jwt as pyjwt  # PyJWT -- aliased so it reads unambiguously next to `cwt`
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cwt import COSEKey, CWTClaims

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
    cwt_signing_key: COSEKey,
    jwt_verify_key=None,
    jwt_algorithms=None,
    audience=None,
) -> bytes:
    """
    Convert a signed JWT into a freshly-signed CWT.

    A JWT's JWS signature can't be carried over into COSE -- container
    format, canonicalization, and signature encoding all differ -- so this
    always re-signs: verify (or just decode) the JWT, lift its claims into
    a CWT claims map, and produce a brand-new COSE-signed CWT over them.

    Args:
        jwt_token: the compact-serialized JWT string.
        cwt_signing_key: COSEKey used to sign the resulting CWT.
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
    cwt_claims = jwt_to_cwt_claims(jwt_token, jwt_verify_key, jwt_algorithms, audience)
    return cwt.encode(cwt_claims, cwt_signing_key)


# --------------------------------------------------------------------------
# Re-signing an existing CWT
# --------------------------------------------------------------------------

def resign_cwt(
    cwt_token: bytes,
    old_verify_key: COSEKey,
    new_signing_key: COSEKey,
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

    if refresh_validity:
        for claim_id in (CWTClaims.EXP, CWTClaims.NBF, CWTClaims.IAT):
            claims.pop(claim_id, None)
        ctx = cwt.CWT.new(expires_in=expires_in)
        return ctx.encode(claims, new_signing_key)

    return cwt.encode(claims, new_signing_key)


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
        token, cwt_verify_key, new_cwt_key, refresh_validity=True, expires_in=7200
    )
    print("\n3) Re-signed CWT under a new key, decoded & verified:")
    print("  ", cwt.decode(resigned, new_cwt_verify_key))


if __name__ == "__main__":
    main()
