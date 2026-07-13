# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""JOSE-HPKE (HPKE-0, Integrated Encryption) helpers — draft-ietf-jose-hpke-encrypt-20.

HPKE-0 = DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM, ``mode_base``,
Integrated Encryption (the ``HPKE-0`` alg is itself integrated — draft-20 has no
separate ``enc`` header).  Built on the native HPKE in ``cryptography`` (RFC 9180,
``cryptography.hazmat.primitives.hpke``).  The JOSE-HPKE JWE layer (compact
serialization, empty IV/Tag, ``aad`` = encoded protected header, ``info`` = empty) is
assembled here because no released Python library implements
draft-ietf-jose-hpke-encrypt.

Backend note — ``aad`` is a private API.  JOSE-HPKE-0 binds the protected header as the
AEAD ``aad``, but ``cryptography``'s *public* ``Suite.encrypt``/``decrypt`` accept only
``info``.  The AEAD-with-aad single-shot lives in the private helpers
``_encrypt_with_aad`` / ``_decrypt_with_aad``; this module imports them under a guard and
fails loudly if a future ``cryptography`` release moves them.  This path is conformance-
pinned: ``test_jose_hpke_vector.py`` opens the draft-20 Appendix A.1 published vector.

``cryptography`` returns/accepts the encapsulated key concatenated with the ciphertext
(``enc || ct``); for DHKEM(P-256) ``enc`` is a 65-byte uncompressed point.  The JOSE
compact JWE carries ``enc`` and ``ct`` in separate base64url fields, so seal splits the
blob and open re-concatenates it.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.hazmat.primitives import hpke as _hpke
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.jose_jws import (
    b64u_decode,
    b64u_encode,
    jwk_to_p256_private,
    jwk_to_p256_public,
)

# JOSE-HPKE alg for the only suite this profile allows.  In draft-20 ``HPKE-0`` is itself
# an Integrated-Encryption algorithm: the protected header carries ``alg`` only, with NO
# separate ``enc`` parameter (that split was the older -12 model).
ALG = "HPKE-0"

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
    if header.get("alg") != ALG:
        raise ValueError(f"unsupported JOSE-HPKE alg: {header.get('alg')!r} (this profile allows only {ALG})")

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
    header.setdefault("alg", ALG)
    protected_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    aad = protected_b64.encode("ascii")

    pkr = _as_public_key(recipient_pub)
    blob = _encrypt_with_aad(hpke0_suite(), plaintext, pkr, b"", aad)
    enc_len = _enc_len(pkr)
    enc, ct = blob[:enc_len], blob[enc_len:]
    # protected '.' enc '.' (empty IV) '.' ciphertext '.' (empty Tag)
    return ".".join([protected_b64, b64u_encode(enc), "", b64u_encode(ct), ""])


__all__ = [
    "ALG",
    "b64u_decode",
    "b64u_encode",
    "hpke0_suite",
    "open_integrated",
    "seal_integrated",
]
