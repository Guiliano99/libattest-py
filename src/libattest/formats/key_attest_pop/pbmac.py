# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""PoP-form computation and verification for the KeyAttestPoP scheme (v2).

The scheme supports two interchangeable proof-of-possession forms,
chosen by the attester at compute time and self-described inside the
:class:`KeyAttestPoPProof` SEQUENCE via its
:class:`AlgorithmIdentifier`:

* **PBMAC1** (RFC 4210 §5.1.3.1 PasswordBasedMac) —
  :func:`compute_key_attest_pop_proof_pbm`.  Binds the recovered
  challenge ``C`` to the attestation nonce ``N`` via
  ``HMAC(BASEKEY(C, salt), N)``.  The MockCA holds both ``C`` and
  ``N`` so it can recompute and constant-time-compare.

* **RSA-SHA256** (RFC 4055 ``sha256WithRSAEncryption``) —
  :func:`compute_key_attest_pop_proof_rsa_sha256`.  Signs the
  attestation nonce ``N`` with the to-be-attested RSA private key.
  ``C`` is decrypted (proof of possession is in the decryption itself)
  but its plaintext value is not used in this form.

The dispatching verifier :func:`verify_key_attest_pop_proof` is what
the MockCA's ``KeyAttestTpmVerifier.verify_pop`` calls.
"""

from __future__ import annotations

import hashlib
import hmac as _stdlib_hmac
import os
from typing import Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc9480

from libattest.formats.key_attest_pop.structures import (
    ID_PASSWORD_BASED_MAC,
    ID_SHA256_WITH_RSA_ENCRYPTION,
    KeyAttestPoPProof,
    prepare_key_attest_pop_proof,
)

# ── OID constants (RFC 4210 §5.1.3.1 / RFC 4231 §3.1) ───────────────────────

#: ``id-sha256`` (NIST OIW).
SHA256_OID: str = "2.16.840.1.101.3.4.2.1"

#: ``id-hmacWithSHA256`` (RFC 4231 §3.1).
HMAC_SHA256_OID: str = "1.2.840.113549.2.9"

DEFAULT_ITERATIONS: int = 1000
DEFAULT_SALT_LEN: int = 16

#: PoP-form selector accepted by :func:`compute_key_attest_pop_proof`.
PBM_FORM: str = "pbm"
RSA_FORM: str = "rsa-sha256"

#: ASN.1 NULL encoded as DER.  Used as ``algorithm.parameters`` for the
#: RSA-SHA256 form (``sha256WithRSAEncryption`` per RFC 4055 §1).
_NULL_DER: bytes = bytes(_der_encoder.encode(univ.Null()))


# ── PBMAC1 primitive ────────────────────────────────────────────────────────


def compute_password_based_mac(
    data: bytes,
    key: bytes,
    iterations: int = 1000,
    salt: Optional[bytes] = None,
    hash_alg: str = "sha256",
    *,
    mac_hash_alg: Optional[str] = None,
) -> bytes:
    """RFC 4210 §5.1.3.1 PasswordBasedMac (PBMAC1).

    Verbatim port of
    ``cmp-test-suite/resources/cryptoutils.py::compute_password_based_mac``
    so the algorithm implementation stays in lockstep with the canonical
    cmp-test-suite version.  Stdlib ``hashlib`` / ``hmac`` are used in
    place of cmp-test-suite's ``compute_hash`` / ``compute_hmac`` so this
    module has no cross-package dependency.

    :param data: bytes to be MAC'd (in KeyAttestPoP this is the
        attestation nonce ``N``).
    :param key: password-style key fed into the BASEKEY derivation
        (in KeyAttestPoP this is the recovered challenge ``C``).
    :param iterations: number of hash rounds, RFC 4210 default 1000.
    :param salt: optional salt; defaults to a fresh 16-byte random.
    :param hash_alg: name of the OWF hash, e.g. ``"sha256"``.
    :param mac_hash_alg: name of the HMAC hash; defaults to *hash_alg*.
    :returns: HMAC output bytes.
    """
    salt = salt or os.urandom(16)
    if isinstance(key, str):
        key = key.encode("utf-8")

    initial_input = key + salt
    for _ in range(iterations):
        initial_input = hashlib.new(hash_alg, initial_input).digest()

    return _stdlib_hmac.new(
        initial_input, data, mac_hash_alg or hash_alg
    ).digest()


def _prepare_pbm_parameter(
    salt: bytes,
    iterations: int = DEFAULT_ITERATIONS,
    *,
    owf_oid: str = SHA256_OID,
    mac_oid: str = HMAC_SHA256_OID,
) -> rfc9480.PBMParameter:
    """Populate a ``PBMParameter`` SEQUENCE for the proof's algorithm.parameters."""
    if not 1 <= len(salt) <= 128:
        raise ValueError(
            "PBMParameter.salt length must be 1..128 bytes (RFC 4210 §5.1.3.1)"
        )
    if iterations < 1:
        raise ValueError("PBMParameter.iterationCount must be >= 1")

    pbm = rfc9480.PBMParameter()
    pbm["salt"] = salt
    pbm["owf"]["algorithm"] = univ.ObjectIdentifier(owf_oid)
    pbm["iterationCount"] = iterations
    pbm["mac"]["algorithm"] = univ.ObjectIdentifier(mac_oid)
    return pbm


def _hash_alg_name_from_oid(oid: str) -> str:
    """Translate the small set of PBMParameter OIDs we accept to hashlib names."""
    if oid == SHA256_OID:
        return "sha256"
    raise ValueError(f"unsupported PBMParameter owf OID: {oid}")


def _mac_alg_name_from_oid(oid: str) -> str:
    """Translate the HMAC OID to the corresponding hashlib name."""
    if oid == HMAC_SHA256_OID:
        return "sha256"
    raise ValueError(f"unsupported PBMParameter mac OID: {oid}")


# ── KeyAttestPoP — PBMAC form ───────────────────────────────────────────────


def _build_pbm_algorithm(pbm: rfc9480.PBMParameter) -> rfc5280.AlgorithmIdentifier:
    """Wrap *pbm* in an ``AlgorithmIdentifier`` keyed by id-PasswordBasedMac."""
    alg = rfc5280.AlgorithmIdentifier()
    alg["algorithm"] = univ.ObjectIdentifier(ID_PASSWORD_BASED_MAC)
    alg["parameters"] = _der_encoder.encode(pbm)
    return alg


def compute_key_attest_pop_proof_pbm(
    recovered_challenge: bytes,
    attestation_nonce: bytes,
    *,
    salt: Optional[bytes] = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> KeyAttestPoPProof:
    """Build a PBMAC-form :class:`KeyAttestPoPProof`.

    :param recovered_challenge: the challenge nonce ``C`` recovered by
        RSA-decrypting ``KeyAttestPoPChallenge.value``; used as the
        PBMAC1 password.
    :param attestation_nonce: the attestation nonce ``N`` from
        ``NonceResponse.nonce``; used as the PBMAC1 data.
    :param salt: optional salt; defaults to fresh randomness.
    :param iterations: PBMAC1 iteration count.

    The resulting proof carries the populated ``PBMParameter`` (salt +
    iter + owf + mac) inside ``algorithm.parameters`` so the MockCA can
    reproduce the BASEKEY derivation when re-checking.
    """
    if salt is None:
        salt = os.urandom(DEFAULT_SALT_LEN)

    mac = compute_password_based_mac(
        data=attestation_nonce,
        key=recovered_challenge,
        iterations=iterations,
        salt=salt,
    )
    pbm = _prepare_pbm_parameter(salt=salt, iterations=iterations)
    return prepare_key_attest_pop_proof(_build_pbm_algorithm(pbm), mac)


# ── KeyAttestPoP — RSA-SHA256 form ──────────────────────────────────────────


def _build_rsa_sha256_algorithm() -> rfc5280.AlgorithmIdentifier:
    """``AlgorithmIdentifier { sha256WithRSAEncryption, NULL }`` (RFC 4055 §1)."""
    alg = rfc5280.AlgorithmIdentifier()
    alg["algorithm"] = univ.ObjectIdentifier(ID_SHA256_WITH_RSA_ENCRYPTION)
    alg["parameters"] = _NULL_DER
    return alg


def _coerce_rsa_private(
    rsa_private_key: Union[rsa.RSAPrivateKey, bytes, bytearray, memoryview],
) -> rsa.RSAPrivateKey:
    """Accept :class:`RSAPrivateKey`, PEM bytes, or DER bytes."""
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
                "KeyAttestPoP RSA form requires an RSA private key "
                f"(got {type(priv).__name__})"
            )
        return priv
    raise TypeError(
        "rsa_private_key must be an RSAPrivateKey, PEM bytes, or DER bytes "
        f"(got {type(rsa_private_key).__name__})"
    )


def compute_key_attest_pop_proof_rsa_sha256(
    rsa_private_key: Union[rsa.RSAPrivateKey, bytes, bytearray, memoryview],
    attestation_nonce: bytes,
) -> KeyAttestPoPProof:
    """Build an RSA-SHA256-form :class:`KeyAttestPoPProof`.

    The attestation nonce ``N`` is signed with RSA-SSA-PKCS1-v1.5 over
    SHA-256 using *rsa_private_key*.  The recovered challenge ``C`` is
    not used in this form — possession is proven by the signature
    alone (only the SPKI's matching private key can produce it).
    """
    priv = _coerce_rsa_private(rsa_private_key)
    signature = priv.sign(
        attestation_nonce, padding.PKCS1v15(), hashes.SHA256()
    )
    return prepare_key_attest_pop_proof(_build_rsa_sha256_algorithm(), signature)


# ── Dispatcher (top-level builder + verifier) ───────────────────────────────


def compute_key_attest_pop_proof(
    *,
    form: str,
    attestation_nonce: bytes,
    recovered_challenge: bytes,
    rsa_private_key: Union[rsa.RSAPrivateKey, bytes, bytearray, memoryview],
) -> KeyAttestPoPProof:
    """Dispatching helper — picks the form-specific builder.

    Always takes both *recovered_challenge* and *rsa_private_key* (even
    when one is ignored by the chosen form) so the call site doesn't
    need to duplicate the form switch.
    """
    if form == PBM_FORM:
        return compute_key_attest_pop_proof_pbm(
            recovered_challenge=recovered_challenge,
            attestation_nonce=attestation_nonce,
        )
    if form == RSA_FORM:
        return compute_key_attest_pop_proof_rsa_sha256(
            rsa_private_key=rsa_private_key,
            attestation_nonce=attestation_nonce,
        )
    raise ValueError(
        f"unknown KeyAttestPoP form {form!r}; "
        f"expected {PBM_FORM!r} or {RSA_FORM!r}"
    )


def _decode_pbm_parameters(parameters) -> rfc9480.PBMParameter:
    """Decode ``algorithm.parameters`` as a :class:`PBMParameter`.

    Accepts pyasn1 ``Any`` payload bytes or an already-decoded SEQUENCE.
    Raises :class:`ValueError` on decode failure.
    """
    if isinstance(parameters, rfc9480.PBMParameter):
        return parameters
    raw = bytes(parameters) if hasattr(parameters, "asOctets") or isinstance(
        parameters, (univ.Any,)
    ) else None
    if raw is None:
        raw = _der_encoder.encode(parameters)
    decoded, _ = _der_decoder.decode(raw, asn1Spec=rfc9480.PBMParameter())
    return decoded  # type: ignore[return-value]


def verify_key_attest_pop_proof(
    *,
    attestation_nonce: bytes,
    recovered_challenge: Optional[bytes],
    spki_der: Optional[bytes],
    proof: KeyAttestPoPProof,
) -> bool:
    """Recompute and compare *proof*.  Dispatches on the proof algorithm.

    * :data:`ID_PASSWORD_BASED_MAC` — re-run :func:`compute_password_based_mac`
      with ``key=recovered_challenge``, ``data=attestation_nonce``, and
      the salt + iterations carried in ``proof.algorithm.parameters``;
      constant-time compare against ``proof.value``.  Requires
      *recovered_challenge*.
    * :data:`ID_SHA256_WITH_RSA_ENCRYPTION` — load the RSA public key
      from *spki_der* and verify ``proof.value`` as a PKCS#1 v1.5
      SHA-256 signature over *attestation_nonce*.  Requires *spki_der*.

    Returns ``False`` on any decode failure or unsupported algorithm so
    callers can treat verification failures uniformly.
    """
    try:
        alg_oid = str(proof["algorithm"]["algorithm"])
        value = bytes(proof["value"])
    except (KeyError, TypeError):
        return False

    if alg_oid == ID_PASSWORD_BASED_MAC:
        if recovered_challenge is None:
            return False
        try:
            pbm = _decode_pbm_parameters(proof["algorithm"]["parameters"])
            salt = bytes(pbm["salt"])
            iterations = int(pbm["iterationCount"])
            owf_oid = str(pbm["owf"]["algorithm"])
            mac_oid = str(pbm["mac"]["algorithm"])
            owf_alg = _hash_alg_name_from_oid(owf_oid)
            mac_alg = _mac_alg_name_from_oid(mac_oid)
        except (ValueError, TypeError, KeyError):
            return False
        computed = compute_password_based_mac(
            data=attestation_nonce,
            key=recovered_challenge,
            iterations=iterations,
            salt=salt,
            hash_alg=owf_alg,
            mac_hash_alg=mac_alg,
        )
        return _stdlib_hmac.compare_digest(computed, value)

    if alg_oid == ID_SHA256_WITH_RSA_ENCRYPTION:
        if spki_der is None:
            return False
        try:
            pub = serialization.load_der_public_key(spki_der)
        except (ValueError, TypeError):
            return False
        if not isinstance(pub, rsa.RSAPublicKey):
            return False
        try:
            pub.verify(
                value, attestation_nonce,
                padding.PKCS1v15(), hashes.SHA256(),
            )
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001
            return False
        return True

    return False


__all__ = [
    "DEFAULT_ITERATIONS",
    "DEFAULT_SALT_LEN",
    "HMAC_SHA256_OID",
    "PBM_FORM",
    "RSA_FORM",
    "SHA256_OID",
    "compute_key_attest_pop_proof",
    "compute_key_attest_pop_proof_pbm",
    "compute_key_attest_pop_proof_rsa_sha256",
    "compute_password_based_mac",
    "verify_key_attest_pop_proof",
]
