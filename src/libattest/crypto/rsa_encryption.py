# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""RSA encryption / decryption helpers used by the KeyAttestPoP scheme.

This module is a thin layer over :mod:`keyutils_py` so all of the
``AlgorithmIdentifier``-aware decoding (RSAES-OAEP-params parsing, PKCS#1
v1.5 parameter validation, OID dispatch) lives in one well-tested place
upstream.

Two algorithms are in scope, dispatched on the
``AlgorithmIdentifier.algorithm`` OID inside
``KeyAttestPoPChallenge.algorithm``:

* ``rsaEncryption`` (PKCS#1 v1.5) — OID ``1.2.840.113549.1.1.1``,
  ``parameters = NULL``.
* ``id-RSAES-OAEP`` — OID ``1.2.840.113549.1.1.7``,
  ``parameters = RSAES-OAEP-params`` (RFC 8017 §A.2.1).  This module
  builds OAEP with SHA-256 + MGF1-SHA-256 + empty label.

Public surface:

* :func:`build_pkcs1v15_algid` / :func:`build_rsaes_oaep_algid` —
  populate :class:`AlgorithmIdentifier` SEQUENCEs the MockCA puts inside
  ``KeyAttestPoPChallenge.algorithm``.
* :func:`rsa_encrypt` — MockCA-side encrypt; takes a populated
  ``AlgorithmIdentifier`` and dispatches on its OID.
* :func:`rsa_decrypt` — attester-side decrypt; delegates to
  :func:`keyutils_py.decrypt_data_with_public_key_alg_id`, with key-input
  coercion (``RSAPrivateKey`` / PEM bytes / DER bytes).

EC keys are rejected (SPEC §C-1) — both helpers reject non-RSA SPKIs.
"""

from __future__ import annotations

from typing import Union

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from keyutils_py import (
    decrypt_data_with_public_key_alg_id,
    encrypt_data_with_public_key_alg_id,
)
from keyutils_py.exceptions import BadAlg, BadAsn1Data
from keyutils_py.keyutils import prepare_alg_id, prepare_hash_alg_id
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc8017


class RSADecryptError(ValueError):
    """Raised when an RSA ciphertext fails to decrypt.

    Wraps lower-level failures from ``cryptography`` (malformed
    ciphertext, modulus mismatch, wrong key) and from ``keyutils_py``
    (bad OID, malformed RSAES-OAEP-params) so callers catch a single
    exception type.
    """


# ── AlgorithmIdentifier builders ────────────────────────────────────────────


def build_pkcs1v15_algid() -> rfc5280.AlgorithmIdentifier:
    """``AlgorithmIdentifier { rsaEncryption, NULL }`` (PKCS#1 v1.5).

    Used as ``KeyAttestPoPChallenge.algorithm`` when the MockCA encrypts
    the challenge ``C`` under PKCS#1 v1.5 padding.
    """
    return prepare_alg_id(rfc8017.rsaEncryption, value=univ.Null(""))


def build_rsaes_oaep_algid() -> rfc5280.AlgorithmIdentifier:
    """``AlgorithmIdentifier { id-RSAES-OAEP, RSAES-OAEP-params(SHA-256) }``.

    Builds RFC 8017 §A.2.1 ``RSAES-OAEP-params`` with hashFunc =
    id-sha256, maskGenFunc = id-mgf1 over SHA-256, and pSourceFunc
    defaulted.

    .. note::
       ``maskGenFunc.parameters`` is encoded as a **bare hash OID**
       (e.g. DER of ``2.16.840.1.101.3.4.2.1`` for SHA-256), to match
       the reading convention of
       :func:`keyutils_py.get_rsa_oaep_padding`.  RFC 4055 §2.1 strictly
       defines ``MGF1.parameters`` as an ``AlgorithmIdentifier``
       (hashAlgorithm); we follow keyutils_py's lighter convention so
       the same wire format round-trips through their decrypt helper
       without an extra coercion step.
    """
    inner_hash = prepare_hash_alg_id("sha256")

    mgf = rfc5280.AlgorithmIdentifier()
    mgf["algorithm"] = rfc8017.id_mgf1
    mgf["parameters"] = _der_encoder.encode(inner_hash["algorithm"])

    params = rfc4055.RSAES_OAEP_params()
    params["hashFunc"]["algorithm"] = inner_hash["algorithm"]
    if inner_hash["parameters"].isValue:
        params["hashFunc"]["parameters"] = inner_hash["parameters"]
    params["maskGenFunc"]["algorithm"] = mgf["algorithm"]
    params["maskGenFunc"]["parameters"] = mgf["parameters"]
    # pSourceFunc — leave default (omitted on the wire).

    return prepare_alg_id(rfc8017.id_RSAES_OAEP, value=_der_encoder.encode(params))


# ── Encryption (MockCA side) ────────────────────────────────────────────────


def _load_rsa_public_key_from_spki(spki_der: bytes) -> rsa.RSAPublicKey:
    """Decode an SPKI DER blob into an RSA public key."""
    pub = serialization.load_der_public_key(spki_der)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError(
            "KeyAttestPoP requires an RSA SubjectPublicKeyInfo "
            f"(got {type(pub).__name__})"
        )
    if pub.key_size < 2048:
        raise ValueError(
            f"RSA modulus too small: {pub.key_size} bits (minimum 2048)"
        )
    return pub


def _normalise_alg_id(
    alg_id: rfc5280.AlgorithmIdentifier,
) -> rfc5280.AlgorithmIdentifier:
    """Round-trip *alg_id* through DER so its ``parameters`` field is a wire-form ``univ.Any``.

    keyutils_py's encrypt/decrypt helpers check ``rsaEncryption``
    parameters via
    ``isinstance(params, univ.Any) and params.asOctets() == b"\\x05\\x00"``.
    A freshly-built ``AlgorithmIdentifier`` (e.g. via
    :func:`build_pkcs1v15_algid`) carries a structured ``univ.Null``
    Asn1Item in that slot, which fails the wire-form check.

    This helper encodes and re-decodes the AlgorithmIdentifier so the
    ``parameters`` field becomes a ``univ.Any`` carrying the 2-byte NULL
    DER, matching what keyutils_py expects on both sides of the
    encrypt / decrypt symmetry.
    """
    # Late imports to avoid a top-of-module dep cycle on the encoder/decoder.
    from pyasn1.codec.der import decoder as _der_decoder
    der = _der_encoder.encode(alg_id)
    decoded, _rest = _der_decoder.decode(der, asn1Spec=rfc5280.AlgorithmIdentifier())
    return decoded  # type: ignore[return-value]


def rsa_encrypt(
    spki_der: bytes,
    plaintext: bytes,
    alg_id: rfc5280.AlgorithmIdentifier,
) -> bytes:
    """Encrypt *plaintext* under the RSA public key in *spki_der* using *alg_id*.

    Thin wrapper around
    :func:`keyutils_py.encrypt_data_with_public_key_alg_id` — that
    function dispatches on the ``alg_id`` OID, validates
    ``rsaEncryption`` parameters, parses ``RSAES_OAEP_params``, and
    builds the right ``cryptography`` padding.  We add only:

    * key-input coercion (DER-encoded SPKI bytes → ``RSAPublicKey``),
    * an RSA-only / 2048-bit-min policy check (SPEC §C-1),
    * a normalisation pass through DER on the ``alg_id`` so a freshly-
      built ``AlgorithmIdentifier`` (whose ``parameters`` field is a
      pyasn1 ``Null`` / structured Asn1Item) is reshaped to the
      wire-style ``univ.Any`` that keyutils_py's parameter-validation
      logic expects.

    :raises TypeError: if the SPKI is not an RSA key.
    :raises ValueError: on malformed SPKI / parameters / unsupported OID
        (re-raised from keyutils_py).
    """
    pub = _load_rsa_public_key_from_spki(spki_der)
    try:
        return encrypt_data_with_public_key_alg_id(
            pub, _normalise_alg_id(alg_id), plaintext
        )
    except (BadAlg, BadAsn1Data) as exc:
        # Re-raise keyutils_py's policy errors as plain ValueError so callers
        # (and tests) get a stable, well-typed surface independent of the
        # keyutils_py exception hierarchy.
        raise ValueError(str(exc)) from exc


# ── Decryption (attester side) ──────────────────────────────────────────────


def _coerce_rsa_private_key(
    rsa_private_key: Union[rsa.RSAPrivateKey, bytes, bytearray, memoryview],
) -> rsa.RSAPrivateKey:
    """Accept an RSA private key as object, PEM bytes, or DER bytes.

    Selection is automatic — PEM blobs start with ``-----BEGIN``;
    everything else is tried as DER.  The keyutils_py decrypt API
    requires an :class:`RSAPrivateKey` instance, so we coerce here
    before delegating.
    """
    if isinstance(rsa_private_key, rsa.RSAPrivateKey):
        return rsa_private_key
    if isinstance(rsa_private_key, (bytes, bytearray, memoryview)):
        raw = bytes(rsa_private_key)
        if raw.lstrip().startswith(b"-----BEGIN"):
            priv = serialization.load_pem_private_key(raw, password=None)
        else:
            priv = serialization.load_der_private_key(raw, password=None)
        if not isinstance(priv, rsa.RSAPrivateKey):
            raise TypeError(
                "KeyAttestPoP requires an RSA private key "
                f"(got {type(priv).__name__})"
            )
        return priv
    raise TypeError(
        "rsa_private_key must be an RSAPrivateKey, PEM bytes, or DER bytes "
        f"(got {type(rsa_private_key).__name__})"
    )


def rsa_decrypt(
    rsa_private_key: Union[rsa.RSAPrivateKey, bytes, bytearray, memoryview],
    ciphertext: bytes,
    alg_id: rfc5280.AlgorithmIdentifier,
) -> bytes:
    """Decrypt *ciphertext* with *rsa_private_key* using *alg_id*.

    Thin wrapper around
    :func:`keyutils_py.decrypt_data_with_public_key_alg_id` — that
    function already dispatches on OID, decodes ``RSAES_OAEP_params``,
    and validates ``rsaEncryption`` parameters.  We add only:

    * key-input coercion (``RSAPrivateKey`` / PEM / DER) so callers don't
      have to pre-load the key, and
    * a single :class:`RSADecryptError` that wraps the ``cryptography``
      and ``keyutils_py`` exceptions.

    :returns: recovered plaintext (the challenge nonce ``C``).
    """
    priv = _coerce_rsa_private_key(rsa_private_key)
    try:
        return decrypt_data_with_public_key_alg_id(
            priv, _normalise_alg_id(alg_id), ciphertext
        )
    except (ValueError, InvalidKey, BadAlg, BadAsn1Data) as exc:
        raise RSADecryptError(f"RSA decrypt failed: {exc}") from exc


__all__ = [
    "RSADecryptError",
    "build_pkcs1v15_algid",
    "build_rsaes_oaep_algid",
    "rsa_decrypt",
    "rsa_encrypt",
]
