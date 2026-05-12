# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""KeyAttestPoP — TPM key-attestation PoP via RSA-decrypt-challenge + PBMAC1 / RSA-SHA256.

This package owns:

* The ASN.1 structures for the wire format
  (:mod:`libattest.formats.key_attest_pop.structures`) —
  ``KeyAttestPoPChallenge`` (MockCA → attester) and
  ``KeyAttestPoPProof`` (attester → MockCA).
* The PoP-form computation helpers — both PBMAC1 and RSA-SHA256 —
  alongside the dispatching verifier
  (:mod:`libattest.formats.key_attest_pop.pbmac`).

The PBMAC1 implementation is a verbatim port of
``cmp-test-suite/resources/cryptoutils.py::compute_password_based_mac``
so the algorithm stays in lockstep with the canonical cmp-test-suite
version.

Co-locating the algorithm and the SEQUENCE it populates means callers
import a single module, and the structure / encoder / decoder /
compute / verify functions all stay in lockstep when the design
evolves.
"""

from libattest.formats.key_attest_pop.pbmac import (
    DEFAULT_ITERATIONS,
    DEFAULT_SALT_LEN,
    HMAC_SHA256_OID,
    PBM_FORM,
    RSA_FORM,
    SHA256_OID,
    compute_key_attest_pop_proof,
    compute_key_attest_pop_proof_pbm,
    compute_key_attest_pop_proof_rsa_sha256,
    compute_password_based_mac,
    verify_key_attest_pop_proof,
)
from libattest.formats.key_attest_pop.structures import (
    DEFAULT_KEY_ATTEST_POP_OID,
    ID_PASSWORD_BASED_MAC,
    ID_RSA_ENCRYPTION,
    ID_RSAES_OAEP,
    ID_SHA256_WITH_RSA_ENCRYPTION,
    KEY_ATTEST_POP_OID_ENV,
    KeyAttestPoPChallenge,
    KeyAttestPoPProof,
    challenge_algorithm_oid,
    challenge_value,
    decode_key_attest_pop_challenge,
    decode_key_attest_pop_proof,
    encode_key_attest_pop_challenge,
    encode_key_attest_pop_proof,
    prepare_key_attest_pop_challenge,
    prepare_key_attest_pop_proof,
    proof_algorithm_oid,
    proof_value,
    resolve_key_attest_pop_oid,
)

__all__ = [
    "DEFAULT_ITERATIONS",
    "DEFAULT_KEY_ATTEST_POP_OID",
    "DEFAULT_SALT_LEN",
    "HMAC_SHA256_OID",
    "ID_PASSWORD_BASED_MAC",
    "ID_RSAES_OAEP",
    "ID_RSA_ENCRYPTION",
    "ID_SHA256_WITH_RSA_ENCRYPTION",
    "KEY_ATTEST_POP_OID_ENV",
    "KeyAttestPoPChallenge",
    "KeyAttestPoPProof",
    "PBM_FORM",
    "RSA_FORM",
    "SHA256_OID",
    "challenge_algorithm_oid",
    "challenge_value",
    "compute_key_attest_pop_proof",
    "compute_key_attest_pop_proof_pbm",
    "compute_key_attest_pop_proof_rsa_sha256",
    "compute_password_based_mac",
    "decode_key_attest_pop_challenge",
    "decode_key_attest_pop_proof",
    "encode_key_attest_pop_challenge",
    "encode_key_attest_pop_proof",
    "prepare_key_attest_pop_challenge",
    "prepare_key_attest_pop_proof",
    "proof_algorithm_oid",
    "proof_value",
    "resolve_key_attest_pop_oid",
    "verify_key_attest_pop_proof",
]
