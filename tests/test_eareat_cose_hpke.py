# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the COSE-HPKE EAR/EAT evidence path.

Covers the attester wrap (:mod:`libattest.formats.eareat_cose_hpke`) against the
verifier appraisal (:class:`libattest.verifier.eareat_cose_hpke.CoseEatHpkeVerifier`):
positive affirming + the four negatives (tampered ciphertext, wrong ``mock_claim``,
replayed nonce, wrong recipient key).  The COSE-HPKE-0 crypto core itself is covered
separately by ``tests/test_cose_hpke_evidence.py``.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats import eareat_cose_hpke, jose_jws
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier


def _signed_eat(signer: ec.EllipticCurvePrivateKey, nonce_b64u: str, mock_claim: str = "secure") -> str:
    """A minimal ATG-shaped signed EAT-JWS (ES256) binding the nonce + mock_claim."""
    claims = {"eat_nonce": nonce_b64u, "mock_claim": mock_claim, "iss": "test-attester"}
    return jose_jws.sign_es256(claims, signer)


class TestEareatCoseHpke(unittest.TestCase):
    def setUp(self) -> None:
        self.attester = ec.generate_private_key(ec.SECP256R1())
        self.recipient = ec.generate_private_key(ec.SECP256R1())
        self.nonce = b"\x11" * 32
        self.nonce_b64u = jose_jws.b64u_encode(self.nonce)
        self.verifier = CoseEatHpkeVerifier(
            attestation_public_key=self.attester.public_key(),
            reference_mock_claim="secure",
            hpke_recipient_key=self.recipient,
        )

    def _bundle(self, mock_claim: str = "secure", nonce_b64u: str | None = None) -> bytes:
        eat = _signed_eat(self.attester, nonce_b64u or self.nonce_b64u, mock_claim)
        return eareat_cose_hpke.build_cose_evidence_bundle(
            eat, self.recipient.public_key(), signer_key=self.attester
        )

    def test_positive_affirming(self) -> None:
        result = self.verifier.verify_bundle_der(self._bundle(), self.nonce)
        self.assertTrue(result.accepted, result.errors)
        ear_claims = jose_jws.verify_es256(result.payload, self.verifier.ear_verification_pem())
        self.assertEqual(ear_claims["submods"]["ATG_PLUGIN"]["ear.status"], "affirming")
        self.assertEqual(ear_claims["ear.verifier-id"]["developer"], "cose-hpke-verifier")
        self.assertEqual(ear_claims["eat_nonce"], self.nonce_b64u)

    def test_negative_wrong_mock_claim(self) -> None:
        result = self.verifier.verify_bundle_der(self._bundle(mock_claim="insecure"), self.nonce)
        self.assertFalse(result.accepted)

    def test_negative_replayed_nonce(self) -> None:
        # Evidence bound to self.nonce, appraised against a different RA nonce.
        result = self.verifier.verify_bundle_der(self._bundle(), b"\x22" * 32)
        self.assertFalse(result.accepted)

    def test_negative_tampered_ciphertext(self) -> None:
        bundle = bytearray(self._bundle())
        bundle[-4] ^= 0x01  # corrupt the tail of the base64url'd COSE_Encrypt0 (AEAD tag / ciphertext)
        result = self.verifier.verify_bundle_der(bytes(bundle), self.nonce)
        self.assertFalse(result.accepted)

    def test_negative_wrong_recipient_key(self) -> None:
        # Evidence sealed to a DIFFERENT recipient than the verifier holds → HPKE-open fails.
        other = ec.generate_private_key(ec.SECP256R1())
        eat = _signed_eat(self.attester, self.nonce_b64u)
        bundle = eareat_cose_hpke.build_cose_evidence_bundle(eat, other.public_key(), signer_key=self.attester)
        result = self.verifier.verify_bundle_der(bundle, self.nonce)
        self.assertFalse(result.accepted)

    def test_extract_roundtrip(self) -> None:
        eat = _signed_eat(self.attester, self.nonce_b64u)
        stmt = eareat_cose_hpke.build_cose_evidence_statement(
            eat, self.recipient.public_key(), signer_key=self.attester
        )
        cose = eareat_cose_hpke.extract_cose_from_statement(bytes(stmt["stmt"]))
        self.assertIsInstance(cose, (bytes, bytearray))
        self.assertGreater(len(cose), 0)

    def test_statement_oid(self) -> None:
        eat = _signed_eat(self.attester, self.nonce_b64u)
        stmt = eareat_cose_hpke.build_cose_evidence_statement(
            eat, self.recipient.public_key(), signer_key=self.attester
        )
        self.assertEqual(str(stmt["type"]), "1.3.6.1.4.1.99999.20")


if __name__ == "__main__":
    unittest.main()
