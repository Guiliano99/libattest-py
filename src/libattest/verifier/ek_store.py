# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Endorsement-key store: map an EK certificate to its full ``TPM2B_PUBLIC``.

Why this exists
---------------
Software ``TPM2_MakeCredential`` needs the EK's **whole public area** — its
``nameAlg``, ``objectAttributes`` and (crucially) the ``parameters.symmetric``
used for the outer wrap — not just the raw key.  An X.509 EK certificate only
carries the ``SubjectPublicKeyInfo`` (the ``unique`` field), so the verifier
cannot run MakeCredential from the certificate alone.

The device therefore submits **both**: the EK certificate (chain) *and* the
marshalled ``TPM2B_PUBLIC``.  This store keys the public area by the leaf
certificate's SHA-256 fingerprint so the verifier can look it up at challenge
time.  On submit it enforces the trust boundary: the certificate's
``SubjectPublicKeyInfo`` MUST equal the ``TPM2B_PUBLIC``'s key, otherwise the
mapping would be forgeable.

Trust model here is TOFU (trust-on-first-submit): the certificate chain's
signature is **not** validated — a real deployment would validate the leaf
against the TPM manufacturer's Endorsement CA before storing.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tpm2_pytss import TPM2B_PUBLIC

from libattest.verifier.tpm.tpm_keyattest_verifier import TpmKeyAttestVerifier


def _load_leaf(cert_chain_pem: bytes) -> x509.Certificate:
    """Load the first certificate from a PEM chain (the EK leaf)."""
    certs = x509.load_pem_x509_certificates(bytes(cert_chain_pem))
    if not certs:
        raise ValueError("empty EK certificate chain")
    return certs[0]


class EkStore:
    """In-memory ``ek_id -> marshalled TPM2B_PUBLIC`` map plus challenge sessions.

    Not thread-safe and not persistent — it is exactly what a demo verifier
    needs and no more.  Seeds retained by :meth:`make_challenge` are single-use:
    :meth:`verify_seed` pops them.
    """

    def __init__(self) -> None:
        """Initialise empty endorsement and session stores."""
        self._ek_public: dict[str, bytes] = {}  # ek_id -> marshalled TPM2B_PUBLIC
        self._seeds: dict[str, bytes] = {}  # session_id -> retained seed
        self._verifier = TpmKeyAttestVerifier()

    def submit(self, cert_chain_pem: bytes, tpm2b_public_raw: bytes) -> str:
        """Store ``TPM2B_PUBLIC`` keyed by the EK leaf fingerprint; return that ``ek_id``.

        Raises ``ValueError`` if the certificate's ``SubjectPublicKeyInfo`` does
        not match the submitted ``TPM2B_PUBLIC`` (the bind check).
        """
        leaf = _load_leaf(cert_chain_pem)
        pub, _consumed = TPM2B_PUBLIC.unmarshal(bytes(tpm2b_public_raw))

        cert_spki = leaf.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        if cert_spki != pub.to_der():
            raise ValueError("EK cert SubjectPublicKeyInfo does not match TPM2B_PUBLIC key")

        ek_id = hashlib.sha256(leaf.public_bytes(Encoding.DER)).hexdigest()
        self._ek_public[ek_id] = bytes(tpm2b_public_raw)
        return ek_id

    def make_challenge(self, ek_id: str, ak_name: bytes) -> tuple[str, bytes, bytes]:
        """Look up the EK, run software MakeCredential, retain the seed.

        Returns ``(session_id, enc_seed, enc_secret)`` — the seed itself never
        leaves the verifier.  Raises ``KeyError`` for an unknown ``ek_id``.
        """
        ek_public = self._ek_public[ek_id]
        session_id, seed, enc_seed, enc_secret = self._verifier.make_challenge(bytes(ak_name), ek_public)
        self._seeds[session_id] = seed
        return session_id, enc_seed, enc_secret

    def verify_seed(self, session_id: str, seed_sha256_hex: str) -> bool:
        """Return ``True`` iff the device's recovered-seed digest matches the retained seed.

        The session is consumed regardless of outcome (single-use).
        """
        seed = self._seeds.pop(session_id, None)
        if seed is None:
            return False
        expected = hashlib.sha256(seed).hexdigest()
        return hmac.compare_digest(expected, seed_sha256_hex)


__all__ = ["EkStore"]
