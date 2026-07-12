# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier side: appraise key-binding Evidence and emit a signed EAR.

This is where the draft's guarantees are actually enforced. Given
:class:`KeyBindingEvidence` and the nonce it issued, the Verifier:

1. checks the ``TPMS_ATTEST`` is a TPM-generated *certify* statement;
2. verifies the **AK signature** over it (authenticity);
3. checks ``extraData == expected_nonce`` (freshness);
4. checks the certified **Name** equals ``H(TPMT_PUBLIC)`` — the anti-key-
   substitution binding (draft §5.2 step 4/5);
5. derives ``key-attributes`` from the *certified* public area and enforces the
   Relying-Party :class:`KeyBindingPolicy` (draft §6);
6. reconstructs the Subject public key as ``cnf`` and verifies the **proof-of-
   possession** against it (draft §5.2 step 5).

Only if all six pass does it mint an EAR (``EARToken``, draft-ietf-rats-ear-04)
carrying the appraised ``cnf`` + ``key-attributes``, signed with the Verifier's
own ES256 key — reusing the repo's :class:`EARToken` model and ``sign_es256``.
"""

from __future__ import annotations

import time

from attester import TPM_ST_ATTEST_CERTIFY
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from evidence import KeyBindingEvidence
from key_attributes import KeyBindingPolicy, derive_key_attributes
from tpm2_pytss import TPM2B_PUBLIC, TPMT_PUBLIC

from libattest.ear import EARAppraisal, EARToken, EATNonce, TrustworthinessTier
from libattest.formats.jose_jws import p256_public_to_jwk, sign_es256
from libattest.formats.tpm.tpm_name import compute_tpm_name
from libattest.formats.tpm.tpm_signature import verify_tpm_signature
from libattest.formats.tpm.tpms_attest import (
    TPM_GENERATED_VALUE,
    extract_certify_name,
    extract_qualifying_data,
)
from libattest.types import VerifyResult

_TPM_GENERATED_VALUE_BYTES = TPM_GENERATED_VALUE.to_bytes(4, "big")


def _ear_to_wire_claims(token: EARToken) -> dict:
    """Serialise an ``EARToken`` to the repo's dotted EAR wire dialect.

    Matches ``verifier/eareat_hpke``'s ``_ear_token_to_veraison_claims`` (dotted
    ``ear.status`` etc. that ``parse_ear_verdict`` consumes) and additionally
    carries this prototype's ``cnf`` + ``key-attributes`` under ``ear.attester-
    claims`` / ``ear.verifier-claims``.
    """
    submods: dict = {}
    for name, appraisal in token.submods.items():
        entry: dict = {"ear.status": appraisal.status.value}
        if appraisal.nonce is not None:
            entry["eat_nonce"] = appraisal.nonce.as_b64_str()
        if appraisal.attester_claims is not None:
            entry["ear.attester-claims"] = appraisal.attester_claims
        if appraisal.verifier_claims is not None:
            entry["ear.verifier-claims"] = appraisal.verifier_claims
        submods[name] = entry
    claims: dict = {
        "eat_profile": token.eat_profile,
        "iat": token.iat,
        "ear.verifier-id": token.verifier_id,
        "submods": submods,
    }
    if token.nonce is not None:
        claims["eat_nonce"] = token.nonce.as_b64_str()
    return claims


def _load_public_spki(data: bytes):
    """Load an AK public key from SPKI DER/PEM (or an X.509 cert)."""
    for loader in (serialization.load_der_public_key, serialization.load_pem_public_key):
        try:
            return loader(data)
        except ValueError:
            continue
    from cryptography import x509

    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try:
            return loader(data).public_key()
        except ValueError:
            continue
    raise ValueError("AK public key must be SPKI or X.509 certificate bytes")


def subject_public_key_from_tpmt_public(tpmt_public: bytes) -> ec.EllipticCurvePublicKey:
    """Reconstruct the Subject public key from a marshalled ``TPMT_PUBLIC``.

    Uses tpm2-pytss to unmarshal the certified public area and re-export its
    point as SPKI, so ``cnf`` is derived from the exact bytes the AK certified.
    """
    public_area, _consumed = TPMT_PUBLIC.unmarshal(bytes(tpmt_public))
    pem = TPM2B_PUBLIC(publicArea=public_area).to_pem()
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("prototype supports EC (P-256) Subject Keys only")
    return key


class KeyBindingVerifier:
    """Appraises TPM key-binding Evidence and issues an EAR on success."""

    def __init__(self, ear_signing_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        """Use *ear_signing_key* to sign EARs, or generate a fresh P-256 key."""
        self._ear_signing_key = ear_signing_key or ec.generate_private_key(ec.SECP256R1())

    def ear_verification_key(self) -> ec.EllipticCurvePublicKey:
        """Return the public key a Relying Party uses to verify issued EARs."""
        return self._ear_signing_key.public_key()

    def ear_verification_pem(self) -> bytes:
        """Return :meth:`ear_verification_key` as a SubjectPublicKeyInfo PEM."""
        return self.ear_verification_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def appraise(
        self,
        evidence: KeyBindingEvidence,
        *,
        expected_nonce: bytes,
        policy: KeyBindingPolicy,
    ) -> VerifyResult:
        """Appraise *evidence* against *expected_nonce* and *policy*.

        Returns an affirming :class:`VerifyResult` whose ``payload`` is the signed
        EAR JWT, or a contraindicated result carrying the reason(s) it failed.
        """
        # The nonce is the Verifier's own issued value; an out-of-range one is a
        # Verifier misconfiguration (the EAR would carry an invalid EATNonce), so
        # report "unknown" rather than crash or reject the Attester's evidence.
        if not 8 <= len(expected_nonce) <= 64:
            return VerifyResult.unknown(
                f"expected_nonce must be 8..64 bytes (RFC 9711 §4.1), got {len(expected_nonce)}"
            )

        attest = evidence.tpms_attest

        # 1) Structural: TPM-generated certify statement.
        if attest[:4] != _TPM_GENERATED_VALUE_BYTES:
            return VerifyResult.contraindicated("TPMS_ATTEST magic is not TPM_GENERATED_VALUE")
        if len(attest) < 6 or int.from_bytes(attest[4:6], "big") != TPM_ST_ATTEST_CERTIFY:
            return VerifyResult.contraindicated("TPMS_ATTEST type is not TPM_ST_ATTEST_CERTIFY")

        # 2) Authenticity: the AK signed this exact statement.
        try:
            ak_public = _load_public_spki(evidence.ak_public_spki)
            verify_tpm_signature(
                signed_bytes=attest,
                tpmt_signature=evidence.tpmt_signature,
                public_key=ak_public,
            )
        except (InvalidSignature, ValueError) as exc:
            return VerifyResult.contraindicated(f"AK signature over certify does not verify: {exc}")

        # 3) Freshness: the certify covers our nonce.
        try:
            got_nonce = extract_qualifying_data(attest)
        except ValueError as exc:
            return VerifyResult.contraindicated(str(exc))
        if got_nonce != expected_nonce:
            return VerifyResult.contraindicated(
                f"certify nonce mismatch: expected={expected_nonce.hex()} got={got_nonce.hex()}"
            )

        # 4) Key-substitution defence: certified Name == H(presented TPMT_PUBLIC).
        try:
            certified_name = extract_certify_name(attest)
            computed_name = compute_tpm_name(evidence.subject_tpmt_public)
        except ValueError as exc:
            return VerifyResult.contraindicated(str(exc))
        if certified_name != computed_name:
            return VerifyResult.contraindicated(
                "certified Name does not match presented TPMT_PUBLIC (key substitution)"
            )

        # 5) key-attributes from the CERTIFIED public area + RP policy (draft §6).
        attributes = derive_key_attributes(evidence.subject_tpmt_public)
        policy_errors = policy.check(attributes)
        if policy_errors:
            return VerifyResult.contraindicated(*policy_errors)

        # 6) cnf + proof-of-possession: the operational key IS the certified key.
        try:
            subject_public = subject_public_key_from_tpmt_public(evidence.subject_tpmt_public)
        except ValueError as exc:
            return VerifyResult.contraindicated(f"cannot parse certified Subject Key: {exc}")
        try:
            subject_public.verify(evidence.pop_signature, expected_nonce, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return VerifyResult.contraindicated(
                "proof-of-possession does not verify against cnf (Subject Key not controlled)"
            )

        cnf = {"jwk": p256_public_to_jwk(subject_public)}
        ear_jwt = self._build_ear(nonce=expected_nonce, cnf=cnf, attributes=attributes)
        return VerifyResult.affirming(ear_jwt)

    def _build_ear(self, *, nonce: bytes, cnf: dict, attributes) -> str:
        """Build and ES256-sign the EAR that conveys the verified key binding.

        The ``EARToken`` is a validated, self-documenting intermediate; the wire
        claims use the repo's dotted EAR dialect (``ear.status`` etc.) so that
        ``libattest.ear.parse_ear_verdict`` / ``ear_is_affirming`` and the
        ``VeraisonVerifierClient`` can read the verdict.
        """
        appraisal = EARAppraisal(
            status=TrustworthinessTier.AFFIRMING,
            nonce=EATNonce.from_bytes(nonce),
            # Claims extracted from Evidence carry Attester authority (draft-04 §3.1).
            attester_claims={"cnf": cnf, "key-attributes": attributes.to_claim()},
            # The binding verdict itself is the Verifier's own determination.
            verifier_claims={"key-binding": "verified", "evidence-type": "tpm2-certify"},
        )
        token = EARToken(
            iat=int(time.time()),
            verifier_id={"developer": "libattest-key-binding-prototype", "build": "0.1.0"},
            submods={"KEY_BINDING": appraisal},
            nonce=EATNonce.from_bytes(nonce),
        )
        return sign_es256(_ear_to_wire_claims(token), self._ear_signing_key)


__all__ = ["KeyBindingVerifier", "subject_public_key_from_tpmt_public"]
