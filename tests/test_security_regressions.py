# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the fail-open defects found in the architecture audit.

Each test here fails against the pre-fix code and passes after.  They are grouped
by the property they defend rather than by module, because every one of them is a
"the library said yes when it should have said no" case:

* :func:`libattest.verifier.trust.validate_ek_chain` treated any certificate under
  a trusted root as a usable issuer (no ``basicConstraints`` / ``keyUsage`` check).
* :func:`libattest.verifier.eat_appraisal.check_nonce_and_claim` returned
  ``affirming`` for a claimless token when the reference values were empty.
* :func:`libattest.formats.eat_ear.cwt_jwt_utils.open_cose_hpke_evidence` accepted
  unsigned evidence by default while the recipient public key is published.
* :func:`libattest.formats.eat_ear.cwt_jwt_utils.open_integrated` raised an
  uncaught ``AttributeError`` on a crafted protected header, before authentication.
"""

from __future__ import annotations

import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest.formats.eat_ear.cwt_jwt_utils import (
    b64u_encode,
    open_cose_hpke_evidence,
    open_integrated,
    open_unsigned_cose_hpke_evidence,
    seal_cose_hpke_evidence,
)
from libattest.verifier.eat_appraisal import check_nonce_and_claim
from libattest.verifier.trust import validate_ek_chain

_NOT_BEFORE = datetime.datetime(2020, 1, 1)
_NOT_AFTER = datetime.datetime(2035, 1, 1)

# A signed EAT-JWT reused from tests/test_cose_hpke_evidence.py; its contents do not
# matter here, only that seal_cose_hpke_evidence can map it to CWT claims.
STATIC_EAR_JWT = (
    b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
    b"eyJpc3MiOiJodHRwczovL2F0dGVzdGVyLmV4YW1wbGUiLCJzdWIiOiJkZXZpY2UtMDAwNyIsImVhdF9ub25jZSI6"
    b"IkFRSURCQVVHQndnSkNnc01EUTRQRUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEEiLCJzdWJtb2RzIjp7IkFUR19QTFVH"
    b"SU4iOnsiZWFyLnN0YXR1cyI6ImFmZmlybWluZyJ9fX0."
    b"1vLNg-ork7-GLxalJivPBupCczDhWtpU0_FFY76G9M-6nXeEr7RV4AY1wwggSmcMH3Dfpde0ZTzKpm-CBwxa9A"
)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _issue(
    subject: str,
    subject_key: ec.EllipticCurvePrivateKey,
    issuer: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool,
    path_length: int | None = None,
) -> x509.Certificate:
    """Issue one certificate, stamping BasicConstraints/KeyUsage to match *ca*."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return builder.sign(issuer_key, hashes.SHA256())


# ── validate_ek_chain: a non-CA certificate must not be usable as an issuer ──────
def test_non_ca_certificate_cannot_act_as_issuer() -> None:
    """GIVEN a leaf forged under a non-CA end-entity cert WHEN validated THEN it is rejected.

    Pre-fix this returned ``None`` (accepted): every chain link was signature-checked
    but nothing asserted the issuer was allowed to issue, so any end-entity
    certificate under a trusted root could mint a chain that validates.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    ee_key = ec.generate_private_key(ec.SECP256R1())
    forged_key = ec.generate_private_key(ec.SECP256R1())

    root = _issue("root", root_key, "root", root_key, ca=True)
    # A perfectly ordinary end-entity certificate issued by the trusted root.
    ee_cert = _issue("plain-ee", ee_key, "root", root_key, ca=False)
    # ...which the attacker then uses to sign a leaf of their choosing.
    forged_leaf = _issue("forged-ak", forged_key, "plain-ee", ee_key, ca=False)

    with pytest.raises(ValueError, match="not a CA|basicConstraints|key_cert_sign"):
        validate_ek_chain(chain=[forged_leaf, ee_cert], roots=[root])


def test_non_ca_trust_root_is_rejected() -> None:
    """GIVEN a configured root that is not a CA WHEN a chain terminates at it THEN reject."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    non_ca_root = _issue("root", root_key, "root", root_key, ca=False)
    leaf = _issue("ak", leaf_key, "root", root_key, ca=False)

    with pytest.raises(ValueError, match="not a CA|basicConstraints|key_cert_sign"):
        validate_ek_chain(chain=[leaf], roots=[non_ca_root])


def test_path_length_constraint_is_enforced() -> None:
    """GIVEN a root with pathLen=0 WHEN an intermediate sits below it THEN reject."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _issue("root", root_key, "root", root_key, ca=True, path_length=0)
    intermediate = _issue("inter", inter_key, "root", root_key, ca=True, path_length=0)
    leaf = _issue("ak", leaf_key, "inter", inter_key, ca=False)

    with pytest.raises(ValueError, match="path"):
        validate_ek_chain(chain=[leaf, intermediate], roots=[root])


def test_valid_chain_still_validates() -> None:
    """GIVEN a well-formed CA chain WHEN validated THEN it is accepted (no regression)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())

    root = _issue("root", root_key, "root", root_key, ca=True, path_length=1)
    intermediate = _issue("inter", inter_key, "root", root_key, ca=True, path_length=0)
    leaf = _issue("ak", leaf_key, "inter", inter_key, ca=False)

    validate_ek_chain(chain=[leaf, intermediate], roots=[root])


# ── check_nonce_and_claim: empty inputs must not appraise as affirming ───────────
def test_empty_claims_and_empty_reference_are_not_affirming() -> None:
    """GIVEN an empty claims map and empty reference values THEN the verdict is not affirming.

    Pre-fix ``check_nonce_and_claim({}, b"", "")`` returned
    ``("affirming", "all checks passed")``: the absent ``eat_nonce`` decoded to
    ``b""`` which equalled the empty expected nonce, and the absent ``mock_claim``
    defaulted to ``""`` which equalled the empty reference.
    """
    status, reason = check_nonce_and_claim({}, b"", "")
    assert status != "affirming", reason


def test_empty_expected_nonce_is_rejected() -> None:
    """GIVEN a token with real claims but no RA nonce to check against THEN reject."""
    status, _ = check_nonce_and_claim({"eat_nonce": "", "mock_claim": "secure"}, b"", "secure")
    assert status != "affirming"


def test_empty_reference_claim_is_rejected() -> None:
    """GIVEN a real nonce but no reference value to appraise against THEN reject."""
    nonce = b"\x07" * 32
    claims = {"eat_nonce": b64u_encode(nonce), "mock_claim": ""}
    status, _ = check_nonce_and_claim(claims, nonce, "")
    assert status != "affirming"


def test_matching_nonce_and_claim_still_affirms() -> None:
    """GIVEN a matching nonce and reference claim THEN it still affirms (no regression)."""
    nonce = b"\x07" * 32
    claims = {"eat_nonce": b64u_encode(nonce), "mock_claim": "secure"}
    status, _ = check_nonce_and_claim(claims, nonce, "secure")
    assert status == "affirming"


# ── open_cose_hpke_evidence: the signature layer is not optional ─────────────────
def test_unsigned_cose_evidence_is_refused_by_the_default_opener() -> None:
    """GIVEN encrypt-only COSE evidence WHEN opened by the signed opener THEN it is refused.

    The recipient public key is published in ``respInfo``, so anyone can seal to it.
    Only the inner ``COSE_Sign1`` distinguishes attester-authored evidence.
    """
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    signer = ec.generate_private_key(ec.SECP256R1())
    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_priv.public_key())

    with pytest.raises(ValueError, match="COSE_Sign1|unsigned|signature"):
        open_cose_hpke_evidence(sealed, recipient_priv, signer.public_key())


def test_unsigned_opener_is_explicit_and_still_works() -> None:
    """GIVEN the encrypt-only form WHEN opened by the explicit unsigned opener THEN it works."""
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_priv.public_key())

    claims = open_unsigned_cose_hpke_evidence(sealed, recipient_priv)
    assert claims["sub"] == "device-0007"


def test_signed_cose_evidence_roundtrips() -> None:
    """GIVEN sign-then-encrypt evidence THEN the signed opener returns its claims."""
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    signer = ec.generate_private_key(ec.SECP256R1())
    sealed = seal_cose_hpke_evidence(STATIC_EAR_JWT, recipient_priv.public_key(), signing_key=signer)

    claims = open_cose_hpke_evidence(sealed, recipient_priv, signer.public_key())
    assert claims["sub"] == "device-0007"


# ── open_integrated: a crafted protected header contraindicates, never crashes ───
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"[1, 2, 3]", id="json-array"),
        pytest.param(b'"just-a-string"', id="json-string"),
        pytest.param(b"5", id="json-number"),
        pytest.param(b"null", id="json-null"),
        pytest.param(b"not json at all", id="not-json"),
    ],
)
def test_crafted_protected_header_raises_valueerror(payload: bytes) -> None:
    """GIVEN a protected header that is not a JSON object THEN raise ValueError, not AttributeError.

    Pre-fix the non-object cases reached ``header.get("alg")`` and raised an uncaught
    ``AttributeError``, which the verifier's ``except ValueError`` did not catch — so a
    crafted statement crashed the verifier before authentication instead of
    contraindicating.
    """
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    compact = ".".join([b64u_encode(payload), b64u_encode(b"enc"), "", b64u_encode(b"ct"), ""])

    with pytest.raises(ValueError):
        open_integrated(compact, recipient_priv)


def test_wellformed_header_with_wrong_alg_still_raises_valueerror() -> None:
    """GIVEN a JSON-object header naming another alg THEN it is rejected as before."""
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    header = b64u_encode(json.dumps({"alg": "RSA-OAEP"}).encode())
    compact = ".".join([header, b64u_encode(b"enc"), "", b64u_encode(b"ct"), ""])

    with pytest.raises(ValueError, match="unsupported JOSE-HPKE alg"):
        open_integrated(compact, recipient_priv)


# ── TPM ABC entry point must not affirm without a cryptographic appraisal ────────
def test_tpm_verify_token_does_not_affirm_arbitrary_bytes() -> None:
    """GIVEN accept-all reference values THEN verify_token yields unknown, never affirming.

    Pre-fix this returned ``affirming`` for *any* byte string: the base
    ``verify_token`` ran only the reference handler, never parsed TPMS_ATTEST, never
    checked the AK signature, and ignored the nonce argument entirely.
    ``TpmPlatformVerifier`` inherits it verbatim, so this was the verdict the RA
    engine got for TPM evidence.
    """
    from libattest.types import EarStatus
    from libattest.verifier.reference import AcceptAllReferenceHandler
    from libattest.verifier.tpm.base import TpmReferenceVerifier

    verifier = TpmReferenceVerifier(reference_handler=AcceptAllReferenceHandler())
    result = verifier.verify_token(b"not a TPMS_ATTEST at all", verifier.media_type, b"\x01" * 32)

    assert result.status is not EarStatus.affirming
    assert not result.accepted


def test_tpm_verify_token_requires_a_nonce() -> None:
    """GIVEN no freshness nonce THEN TPM evidence appraisal contraindicates."""
    from libattest.types import EarStatus
    from libattest.verifier.reference import AcceptAllReferenceHandler
    from libattest.verifier.tpm.base import TpmReferenceVerifier

    verifier = TpmReferenceVerifier(reference_handler=AcceptAllReferenceHandler())
    result = verifier.verify_token(b"evidence", verifier.media_type, None)

    assert result.status is EarStatus.contraindicated


def test_tpm_verify_token_still_contraindicates_on_reference_mismatch() -> None:
    """GIVEN a rejecting reference handler THEN it still contraindicates (no regression)."""
    from libattest.types import EarStatus
    from libattest.verifier.reference import ReferenceCheckResult, VerifierReferenceHandler
    from libattest.verifier.tpm.base import TpmReferenceVerifier

    class RejectAll(VerifierReferenceHandler):
        def handle_evidence(self, evidence, *, attester_id=None):
            return ReferenceCheckResult(accepted=False, reason="digest mismatch")

    verifier = TpmReferenceVerifier(reference_handler=RejectAll())
    result = verifier.verify_token(b"evidence", verifier.media_type, b"\x01" * 32)

    assert result.status is EarStatus.contraindicated
    assert "digest mismatch" in " ".join(result.errors)
