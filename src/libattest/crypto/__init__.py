# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""General cryptographic helpers used outside the attestation-evidence packages.

Currently exposes:

* :mod:`libattest.crypto.rsa_encryption` — RSA encryption / decryption
  helpers (``rsaEncryption`` PKCS#1 v1.5 and ``id-RSAES-OAEP`` SHA-256)
  used by the MockCA (encrypt-with-SPKI) and the attester
  (decrypt-with-private-key) under the KeyAttestPoP scheme.

The KeyAttestPoP PBMAC1 computation lives next to its ASN.1 structures
in :mod:`libattest.formats.key_attest_pop.pbmac` so the algorithm and
the SEQUENCE it populates stay co-located.
"""

from libattest.crypto.rsa_encryption import (
    RSADecryptError,
    build_pkcs1v15_algid,
    build_rsaes_oaep_algid,
    rsa_decrypt,
    rsa_encrypt,
)

__all__ = [
    "RSADecryptError",
    "build_pkcs1v15_algid",
    "build_rsaes_oaep_algid",
    "rsa_decrypt",
    "rsa_encrypt",
]
