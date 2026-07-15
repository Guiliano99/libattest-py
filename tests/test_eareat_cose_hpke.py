# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end tests for the COSE-HPKE EAR/EAT evidence path.

Covers the attester wrap (:mod:`libattest.formats.eareat_hpke`) against the
verifier appraisal (:class:`libattest.verifier.eareat_cose_hpke.CoseEatHpkeVerifier`):
positive affirming + the four negatives (tampered ciphertext, wrong ``mock_claim``,
replayed nonce, wrong recipient key).  The COSE-HPKE-0 crypto core itself is covered
separately by ``tests/test_cose_hpke_evidence.py``.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ

from libattest import get_oid_for_stmt_name
from libattest.asn1_utils import try_decode_pyasn1
from libattest.attester.evidence_bridge import generate_cwt_evidence
from libattest.formats import eareat_hpke
from libattest.formats.cmw import CMW
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.csrattest import prepare_attestation_statement
from libattest.verifier.eareat_cose_hpke import CoseEatHpkeVerifier


def _signed_eat(signer: ec.EllipticCurvePrivateKey, nonce_b64u: str, mock_claim: str = "secure") -> str:
    """Create a minimal ATG-shaped signed EAT-JWS binding the nonce and mock claim."""
    claims = {"eat_nonce": nonce_b64u, "mock_claim": mock_claim, "iss": "test-attester"}
    return cwt_jwt_utils.sign_es256(claims, signer)


class TestEareatCoseHpke(unittest.TestCase):
    """Exercise COSE-HPKE attestation generation and verifier appraisal."""

    def setUp(self) -> None:
        """Create fresh attester and recipient keys plus the configured verifier."""
        self.attester = ec.generate_private_key(ec.SECP256R1())
        self.recipient = ec.generate_private_key(ec.SECP256R1())
        self.nonce = b"\x11" * 32
        self.nonce_b64u = cwt_jwt_utils.b64u_encode(self.nonce)
        self.verifier = CoseEatHpkeVerifier(
            attestation_public_key=self.attester.public_key(),
            reference_mock_claim="secure",
            hpke_recipient_key=self.recipient,
        )

    def _bundle(self, mock_claim: str = "secure", nonce_b64u: str | None = None) -> bytes:
        eat = _signed_eat(self.attester, nonce_b64u or self.nonce_b64u, mock_claim)
        return eareat_hpke.build_cose_evidence_bundle(eat, self.recipient.public_key(), signer_key=self.attester)

    def test_positive_affirming(self) -> None:
        """Verify that valid COSE-HPKE evidence produces an affirming EAR."""
        result = self.verifier.verify_bundle_der(self._bundle(), self.nonce)
        self.assertTrue(result.accepted, result.errors)
        ear_claims = cwt_jwt_utils.verify_es256(result.payload, self.verifier.ear_verification_pem())
        self.assertEqual(ear_claims["submods"]["ATG_PLUGIN"]["ear.status"], "affirming")
        self.assertEqual(ear_claims["ear.verifier-id"]["developer"], "cose-hpke-verifier")
        self.assertEqual(ear_claims["eat_nonce"], self.nonce_b64u)

    def test_negative_wrong_mock_claim(self) -> None:
        """Reject evidence whose appraised mock claim differs from the reference."""
        result = self.verifier.verify_bundle_der(self._bundle(mock_claim="insecure"), self.nonce)
        self.assertFalse(result.accepted)

    def test_negative_replayed_nonce(self) -> None:
        """Reject evidence appraised against a different freshness nonce."""
        # Evidence bound to self.nonce, appraised against a different RA nonce.
        result = self.verifier.verify_bundle_der(self._bundle(), b"\x22" * 32)
        self.assertFalse(result.accepted)

    def test_negative_tampered_ciphertext(self) -> None:
        """Reject evidence with a modified COSE ciphertext or authentication tag."""
        bundle = bytearray(self._bundle())
        bundle[-4] ^= 0x01  # corrupt the tail of the embedded COSE_Encrypt0 (AEAD tag / ciphertext)
        result = self.verifier.verify_bundle_der(bytes(bundle), self.nonce)
        self.assertFalse(result.accepted)

    def test_negative_wrong_recipient_key(self) -> None:
        """Reject evidence encrypted for a recipient other than the verifier."""
        # Evidence sealed to a DIFFERENT recipient than the verifier holds → HPKE-open fails.
        other = ec.generate_private_key(ec.SECP256R1())
        eat = _signed_eat(self.attester, self.nonce_b64u)
        bundle = eareat_hpke.build_cose_evidence_bundle(eat, other.public_key(), signer_key=self.attester)
        result = self.verifier.verify_bundle_der(bundle, self.nonce)
        self.assertFalse(result.accepted)

    def test_extract_roundtrip(self) -> None:
        """Extract raw COSE bytes from the CMW cbor evidence statement."""
        eat = _signed_eat(self.attester, self.nonce_b64u)
        stmt = eareat_hpke.build_cose_evidence_statement(
            eat, self.recipient.public_key(), signer_key=self.attester
        )
        cose = eareat_hpke.extract_cose_from_statement(bytes(stmt["stmt"]))
        self.assertIsInstance(cose, (bytes, bytearray))
        self.assertGreater(len(cose), 0)

    def test_public_generator_returns_a_cmw_statement_payload(self) -> None:
        """GIVEN signed EAT WHEN the facade generates CWT THEN a caller can add DER(CMW)."""
        eat = _signed_eat(self.attester, self.nonce_b64u)

        payload = generate_cwt_evidence(eat, self.recipient.public_key(), self.attester)

        cmw = try_decode_pyasn1(payload, CMW)
        self.assertEqual(cmw.getName(), "cbor")
        statement = prepare_attestation_statement(
            univ.ObjectIdentifier(get_oid_for_stmt_name("cose-hpke-evidence")), payload
        )
        self.assertEqual(bytes(statement["stmt"]), payload)

    def test_statement_oid(self) -> None:
        """Emit the dedicated COSE-HPKE evidence statement OID."""
        eat = _signed_eat(self.attester, self.nonce_b64u)
        stmt = eareat_hpke.build_cose_evidence_statement(
            eat, self.recipient.public_key(), signer_key=self.attester
        )
        self.assertEqual(str(stmt["type"]), "1.3.6.1.4.1.99999.20")
        self.assertEqual(str(stmt["type"]), get_oid_for_stmt_name("cose-hpke-evidence"))


if __name__ == "__main__":
    unittest.main()
