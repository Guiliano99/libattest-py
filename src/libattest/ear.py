# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""EAR (Entity Attestation Result) JWT helpers.

References
----------
draft-ietf-rats-ar4si: Attestation Results for Secure Interactions
  https://datatracker.ietf.org/doc/draft-ietf-rats-ar4si/

"""

from __future__ import annotations

import base64
import json
import logging

from cryptography.hazmat.primitives.asymmetric import ec

logger = logging.getLogger(__name__)

_AFFIRMING = "affirming"


def parse_ear_verdict(ear_jwt: str) -> dict[str, str]:
    """Return ``{submod_name: ear.status}`` for every submodule in the EAR JWT.

    The JWT signature is **not** verified — use this only for verdict
    inspection inside a trusted verification pipeline, never for
    authentication.

    Parameters
    ----------
    ear_jwt:
        Compact-serialized JWT carrying an EAR payload.

    Returns
    -------
    dict[str, str]
        Mapping from submodule name to its ``ear.status`` value.  Submodules
        that do not carry an ``ear.status`` field receive the value
        ``"unknown"``.

    Raises
    ------
    ValueError
        If *ear_jwt* is not a well-formed JWT or its payload cannot be
        base64-decoded or JSON-parsed.

    """
    parts = ear_jwt.split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT: fewer than two '.' delimiters")
    pad = (4 - len(parts[1]) % 4) % 4
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * pad))
    except Exception as exc:
        raise ValueError(f"Failed to decode EAR JWT payload: {exc}") from exc
    return {name: str(submod.get("ear.status", "unknown")) for name, submod in payload.get("submods", {}).items()}


def verify_ear_jwt(ear_jwt: str, public_key: "ec.EllipticCurvePublicKey") -> bool:
    """Verify the ES256 signature on *ear_jwt* using *public_key*.

    JWT ES256 carries the raw R||S signature (64 bytes for P-256), not DER.
    This function converts to DER before calling the ``cryptography`` verifier.

    Parameters
    ----------
    ear_jwt:
        Compact-serialized JWT (header.payload.signature).
    public_key:
        P-256 public key whose corresponding private key signed the JWT.

    Returns
    -------
    bool
        ``True`` when the signature is valid, ``False`` on any error.

    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        parts = ear_jwt.split(".")
        if len(parts) != 3:
            logger.warning("verify_ear_jwt: not a compact JWT (expected 3 parts)")
            return False

        message = (parts[0] + "." + parts[1]).encode("ascii")
        pad = (4 - len(parts[2]) % 4) % 4
        sig_bytes = base64.urlsafe_b64decode(parts[2] + "=" * pad)

        # ES256 uses raw R||S (32 bytes each for P-256), not DER.
        if len(sig_bytes) != 64:
            logger.warning("verify_ear_jwt: unexpected ES256 signature length %d", len(sig_bytes))
            return False

        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        der_sig = encode_dss_signature(r, s)

        public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        logger.warning("verify_ear_jwt: signature verification FAILED")
        return False
    except Exception as exc:  # noqa: BLE001
        logger.warning("verify_ear_jwt: unexpected error: %s", exc)
        return False


def ear_is_affirming(ear_jwt: str) -> bool:
    """Return ``True`` iff every submodule carries ``ear.status == 'affirming'``.

    Returns ``False`` (never raises) on parse errors, logging a warning instead.
    An EAR with zero submodules also returns ``False``.
    """
    try:
        verdicts = parse_ear_verdict(ear_jwt)
    except ValueError as exc:
        logger.warning("Failed to parse EAR JWT verdict: %s", exc)
        return False
    if not verdicts:
        logger.warning("EAR JWT contains no submodules")
        return False
    for name, verdict in verdicts.items():
        if verdict != _AFFIRMING:
            logger.warning("EAR submod %r: ear.status=%r", name, verdict)
            return False
    return True
