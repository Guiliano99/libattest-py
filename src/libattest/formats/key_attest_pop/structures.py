# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for the KeyAttestPoP scheme (SPEC §DR-1, redesign v2).

Two SEQUENCEs:

* ``KeyAttestPoPChallenge`` — produced by the MockCA and carried inside
  ``NonceResponse.responseParams`` as a typed ``ChallengeParam``.  Encrypts
  a fresh challenge nonce ``C`` against the attester's SPKI.

      ``KeyAttestPoPChallenge ::= SEQUENCE {
            algorithm  AlgorithmIdentifier,   -- decryption algorithm
            value      OCTET STRING            -- ciphertext of C
       }``

* ``KeyAttestPoPProof`` — produced by the attester and carried as a CSR
  / certTemplate extension under ``KEY_ATTEST_POP_OID`` (and copied
  verbatim onto the issued cert as an audit-only extension).  The bundle
  to the verifier no longer carries any KeyAttestPoP statement; the PoP
  loop is strictly between the attester and the MockCA.

      ``KeyAttestPoPProof ::= SEQUENCE {
            algorithm  AlgorithmIdentifier,   -- proof form
            value      OCTET STRING            -- MAC bytes or signature bytes
       }``

The MockCA picks the **decryption algorithm** for the challenge:

+-------------------------------------+--------------------------+
| algorithm.algorithm OID             | algorithm.parameters     |
+=====================================+==========================+
| ``rsaEncryption`` (PKCS#1 v1.5)     | ``NULL``                 |
| 1.2.840.113549.1.1.1                |                          |
+-------------------------------------+--------------------------+
| ``id-RSAES-OAEP``                   | ``RSAES-OAEP-params``    |
| 1.2.840.113549.1.1.7                | (RFC 8017 §A.2.1)        |
+-------------------------------------+--------------------------+

The attester picks the **proof form**:

+------------------------------+----------------------+--------------------+
| algorithm.algorithm OID      | algorithm.parameters | value              |
+==============================+======================+====================+
| ``id-PasswordBasedMac``      | ``PBMParameter``     | ``PBMAC1(C, N)``   |
| 1.2.840.113533.7.66.13       | (RFC 4210 §5.1.3.1)  | (32 B for SHA-256) |
+------------------------------+----------------------+--------------------+
| ``sha256WithRSAEncryption``  | ``NULL``             | RSA-SSA-PKCS1-v1.5 |
| 1.2.840.113549.1.1.11        |                      | over SHA-256(N)    |
+------------------------------+----------------------+--------------------+

``N`` is the plaintext attestation nonce returned in ``NonceResponse.nonce``;
``C`` is the plaintext challenge recovered from
``KeyAttestPoPChallenge.value`` by RSA-decrypting with the attester's
private key.
"""

from __future__ import annotations

import os
from typing import Optional

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import namedtype, univ
from pyasn1_alt_modules import rfc5280, rfc9480

# ── OID constant + env override ─────────────────────────────────────────────

#: Name of the env var used by all components in the stack to override
#: the default OID for testing / namespace conflicts.  Read on demand by
#: :func:`resolve_key_attest_pop_oid` — never cached at import time so
#: docker-compose env changes take effect at process start.
KEY_ATTEST_POP_OID_ENV: str = "KEY_ATTEST_POP_OID"

#: Default dotted OID — a private-enterprise arc reserved for this demo.
DEFAULT_KEY_ATTEST_POP_OID: str = "1.3.6.1.4.1.99999.2"


def resolve_key_attest_pop_oid() -> str:
    """Return the OID dotted string from env, falling back to the default."""
    return os.environ.get(KEY_ATTEST_POP_OID_ENV, DEFAULT_KEY_ATTEST_POP_OID)


# ── Algorithm OID constants ─────────────────────────────────────────────────

# Decryption algorithms accepted in ``KeyAttestPoPChallenge.algorithm``.

#: ``rsaEncryption`` per RFC 8017 §A.1 — PKCS#1 v1.5 encryption padding.
ID_RSA_ENCRYPTION: str = "1.2.840.113549.1.1.1"

#: ``id-RSAES-OAEP`` per RFC 8017 §A.2.1 — OAEP encryption padding.  When
#: this OID is used the algorithm parameters carry ``RSAES-OAEP-params``
#: (hashFunc / maskGenFunc / pSourceFunc).
ID_RSAES_OAEP: str = "1.2.840.113549.1.1.7"

# Proof-form algorithms in ``KeyAttestPoPProof.algorithm``.

#: ``id-PasswordBasedMac`` (RFC 4210 §5.1.3.1).  Used as
#: ``KeyAttestPoPProof.algorithm.algorithm`` for the PBMAC form.  The
#: parameters carry a ``PBMParameter`` SEQUENCE with the salt + iter + owf
#: + mac the attester used so the MockCA can reproduce BASEKEY derivation.
ID_PASSWORD_BASED_MAC: str = "1.2.840.113533.7.66.13"

#: ``sha256WithRSAEncryption`` (RFC 4055).  Used as
#: ``KeyAttestPoPProof.algorithm.algorithm`` for the RSA-SHA256 form.
ID_SHA256_WITH_RSA_ENCRYPTION: str = "1.2.840.113549.1.1.11"


# ── ASN.1 schema ────────────────────────────────────────────────────────────


class KeyAttestPoPChallenge(univ.Sequence):
    """``KeyAttestPoPChallenge ::= SEQUENCE { algorithm, value }``.

    Carried inside ``NonceResponse.responseParams`` as a
    ``ChallengeParam {type = KEY_ATTEST_POP_OID, value = DER(this)}``.

    The attester decrypts ``value`` using the algorithm in ``algorithm``
    and recovers the plaintext challenge nonce ``C``.  Possession of
    ``C`` is the proof of possession (used as the PBMAC1 password in the
    PBMAC form, or simply discarded in the RSA-SHA256 form where the
    binding comes from signing the attestation nonce ``N`` directly).
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("value", univ.OctetString()),
    )


class KeyAttestPoPProof(univ.Sequence):
    """``KeyAttestPoPProof ::= SEQUENCE { algorithm, value }``.

    Algorithm-tagged proof structure (CMS-style).  ``algorithm``
    discriminates the PoP form; ``value`` carries the raw output:

    +------------------------------+----------------------+--------------------+
    | algorithm.algorithm OID      | algorithm.parameters | value              |
    +==============================+======================+====================+
    | id-PasswordBasedMac          | PBMParameter         | ``PBMAC1(C, N)``   |
    | (1.2.840.113533.7.66.13)     | (RFC 4210 §5.1.3.1)  | (32 B for SHA-256) |
    +------------------------------+----------------------+--------------------+
    | sha256WithRSAEncryption      | NULL                 | RSA-SSA-PKCS1-v1.5 |
    | (1.2.840.113549.1.1.11)      |                      | over SHA-256(N)    |
    +------------------------------+----------------------+--------------------+

    Lives only as a CSR / cert extension under ``KEY_ATTEST_POP_OID``.
    Removed from the AttestationBundle in v2 — the PoP loop is strictly
    between attester and MockCA; the verifier never sees this structure.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("value", univ.OctetString()),
    )


# ── Builders ────────────────────────────────────────────────────────────────


def prepare_key_attest_pop_challenge(
    algorithm: rfc5280.AlgorithmIdentifier,
    value: bytes,
) -> KeyAttestPoPChallenge:
    """Populate a :class:`KeyAttestPoPChallenge` SEQUENCE.

    :param algorithm: a populated :class:`rfc5280.AlgorithmIdentifier`
        whose ``algorithm`` is one of :data:`ID_RSA_ENCRYPTION` or
        :data:`ID_RSAES_OAEP`.  Use the helpers in
        :mod:`libattest.crypto.rsa_encryption` to build it.
    :param value: the RSA ciphertext bytes (the encrypted challenge ``C``).
    """
    challenge = KeyAttestPoPChallenge()
    challenge["algorithm"] = algorithm
    challenge["value"] = value
    return challenge


def prepare_key_attest_pop_proof(
    algorithm: rfc5280.AlgorithmIdentifier,
    value: bytes,
) -> KeyAttestPoPProof:
    """Populate a :class:`KeyAttestPoPProof` SEQUENCE.

    :param algorithm: a populated :class:`rfc5280.AlgorithmIdentifier`
        whose ``algorithm`` is one of :data:`ID_PASSWORD_BASED_MAC`
        (parameters = PBMParameter) or
        :data:`ID_SHA256_WITH_RSA_ENCRYPTION` (parameters = NULL).  Use
        the helpers in :mod:`libattest.formats.key_attest_pop.pbmac`
        to build it.
    :param value: the per-algorithm proof bytes — HMAC output for PBMAC,
        RSA signature bytes for the RSA-SHA256 form.
    """
    proof = KeyAttestPoPProof()
    proof["algorithm"] = algorithm
    proof["value"] = value
    return proof


# ── DER encode / decode helpers ─────────────────────────────────────────────


def encode_key_attest_pop_challenge(challenge: KeyAttestPoPChallenge) -> bytes:
    """DER-encode a :class:`KeyAttestPoPChallenge`."""
    return _der_encoder.encode(challenge)


def decode_key_attest_pop_challenge(der: bytes) -> KeyAttestPoPChallenge:
    """Decode a :class:`KeyAttestPoPChallenge` from DER.

    :raises ValueError: when the bytes do not decode as the SEQUENCE.
    """
    try:
        decoded, rest = _der_decoder.decode(
            der, asn1Spec=KeyAttestPoPChallenge()
        )
    except Exception as exc:  # noqa: BLE001
        raise ValueError(
            f"failed to decode KeyAttestPoPChallenge: {exc}"
        ) from exc
    if rest:
        raise ValueError("trailing bytes after KeyAttestPoPChallenge SEQUENCE")
    return decoded  # type: ignore[return-value]


def encode_key_attest_pop_proof(proof: KeyAttestPoPProof) -> bytes:
    """DER-encode a :class:`KeyAttestPoPProof`."""
    return _der_encoder.encode(proof)


def decode_key_attest_pop_proof(der: bytes) -> KeyAttestPoPProof:
    """Decode a :class:`KeyAttestPoPProof` from DER.

    :raises ValueError: when the bytes do not decode as the SEQUENCE.
    """
    try:
        decoded, rest = _der_decoder.decode(der, asn1Spec=KeyAttestPoPProof())
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"failed to decode KeyAttestPoPProof: {exc}") from exc
    if rest:
        raise ValueError("trailing bytes after KeyAttestPoPProof SEQUENCE")
    return decoded  # type: ignore[return-value]


# ── Field accessors ─────────────────────────────────────────────────────────


def challenge_algorithm_oid(challenge: KeyAttestPoPChallenge) -> str:
    """Return ``challenge.algorithm.algorithm`` as a dotted string."""
    return str(challenge["algorithm"]["algorithm"])


def challenge_value(challenge: KeyAttestPoPChallenge) -> bytes:
    """Return the raw ciphertext bytes from ``challenge.value``."""
    return bytes(challenge["value"])


def proof_algorithm_oid(proof: KeyAttestPoPProof) -> str:
    """Return ``proof.algorithm.algorithm`` as a dotted string."""
    return str(proof["algorithm"]["algorithm"])


def proof_value(proof: KeyAttestPoPProof) -> bytes:
    """Return the raw bytes of ``proof.value``.

    Interpretation depends on ``proof.algorithm.algorithm``:

    * For ``id-PasswordBasedMac`` — HMAC output bytes.
    * For ``sha256WithRSAEncryption`` — RSA signature bytes.
    """
    return bytes(proof["value"])


__all__ = [
    "DEFAULT_KEY_ATTEST_POP_OID",
    "ID_PASSWORD_BASED_MAC",
    "ID_RSAES_OAEP",
    "ID_RSA_ENCRYPTION",
    "ID_SHA256_WITH_RSA_ENCRYPTION",
    "KEY_ATTEST_POP_OID_ENV",
    "KeyAttestPoPChallenge",
    "KeyAttestPoPProof",
    "challenge_algorithm_oid",
    "challenge_value",
    "decode_key_attest_pop_challenge",
    "decode_key_attest_pop_proof",
    "encode_key_attest_pop_challenge",
    "encode_key_attest_pop_proof",
    "prepare_key_attest_pop_challenge",
    "prepare_key_attest_pop_proof",
    "proof_algorithm_oid",
    "proof_value",
    "resolve_key_attest_pop_oid",
]


# Marker variable to fail-fast on missing pyasn1_alt_modules.
_DEP_CHECK: Optional[type] = rfc9480.PBMParameter
