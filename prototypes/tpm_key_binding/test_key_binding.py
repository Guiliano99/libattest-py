# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103, T201

"""Offline self-test for the TPM key-binding prototype (no TPM required).

Runs under pytest, or standalone as ``python test_key_binding.py`` — every check
is a plain ``assert`` so a broken invariant fails loudly either way. Each test
targets one Verifier gate: valid binding, cnf/PoP identity, key substitution,
nonce freshness, AK-signature tamper, RP policy, and PoP forgery.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from attester import (  # noqa: E402
    STRONG_SUBJECT_ATTRS,
    WEAK_SUBJECT_ATTRS,
    SyntheticKeyBindingAttester,
)
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from key_attributes import KeyBindingPolicy, derive_key_attributes  # noqa: E402
from verifier import KeyBindingVerifier, subject_public_key_from_tpmt_public  # noqa: E402

from libattest.formats.eat_ear.cwt_jwt import ear_is_affirming, verify_ear_jwt  # noqa: E402

_NONCE = b"verifier-issued-nonce-0123456789"  # 32 bytes, >= EATNonce min (8)
_POLICY = KeyBindingPolicy()  # strict defaults: never-extractable, !extractable, local


def _ear_payload(ear_jwt: str) -> dict:
    """Decode (without verifying) the EAR JWT payload for inspection."""
    part = ear_jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def test_valid_binding_affirms_and_ear_verifies():
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    verifier = KeyBindingVerifier()

    result = verifier.appraise(attester.produce(_NONCE), expected_nonce=_NONCE, policy=_POLICY)

    assert result.accepted, result.errors
    ear = result.payload
    assert isinstance(ear, str)
    # The EAR is signed by the Verifier and a Relying Party can verify it ...
    assert verify_ear_jwt(ear, verifier.ear_verification_key())
    # ... and read its verdict with the repo's own helper (dotted-key dialect).
    assert ear_is_affirming(ear)

    payload = _ear_payload(ear)
    submod = payload["submods"]["KEY_BINDING"]
    assert submod["ear.status"] == "affirming"
    attrs = submod["ear.attester-claims"]["key-attributes"]
    assert attrs["never-extractable"] is True
    assert attrs["extractable"] is False
    assert attrs["local"] is True
    assert "cnf" in submod["ear.attester-claims"]
    assert "jwk" in submod["ear.attester-claims"]["cnf"]


def test_cnf_jwk_is_the_certified_subject_key():
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    # cnf is reconstructed from the certified TPMT_PUBLIC ...
    cnf_key = subject_public_key_from_tpmt_public(evidence.subject_tpmt_public)
    # ... and must equal the attester's actual Subject Key.
    assert cnf_key.public_numbers() == attester.subject_private.public_key().public_numbers()


def test_tpm_name_matches_pytss_get_name():
    """compute_tpm_name over our marshalled area must equal a real TPM Name."""
    from cryptography.hazmat.primitives import serialization
    from tpm2_pytss import TPM2_ALG, TPM2B_PUBLIC

    from libattest.formats.tpm.tpm_name import compute_tpm_name

    subj = ec.generate_private_key(ec.SECP256R1())
    pem = subj.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    b = TPM2B_PUBLIC.from_pem(pem, nameAlg=TPM2_ALG.SHA256, objectAttributes=STRONG_SUBJECT_ATTRS)
    assert compute_tpm_name(b.publicArea.marshal()) == bytes(b.get_name())


def test_key_substitution_is_rejected():
    """Swap in a different key's public area: the certified Name no longer matches."""
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    other = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    forged = dataclasses.replace(evidence, subject_tpmt_public=other.produce(_NONCE).subject_tpmt_public)

    result = KeyBindingVerifier().appraise(forged, expected_nonce=_NONCE, policy=_POLICY)
    assert not result.accepted
    assert "key substitution" in result.errors[0]


def test_wrong_nonce_is_rejected():
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    result = KeyBindingVerifier().appraise(
        evidence, expected_nonce=b"a-different-nonce-0000000000000000", policy=_POLICY
    )
    assert not result.accepted
    assert "nonce" in result.errors[0]


def test_tampered_certify_signature_is_rejected():
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    tampered = bytearray(evidence.tpms_attest)
    tampered[-1] ^= 0x01  # flip a byte inside the signed statement
    forged = dataclasses.replace(evidence, tpms_attest=bytes(tampered))

    result = KeyBindingVerifier().appraise(forged, expected_nonce=_NONCE, policy=_POLICY)
    assert not result.accepted
    assert "AK signature" in result.errors[0]


def test_extractable_key_is_rejected_by_policy():
    """A duplicable / importable Subject Key must fail the strict RP policy."""
    attester = SyntheticKeyBindingAttester.generate(WEAK_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    # Sanity: the derived attributes really are weak.
    attrs = derive_key_attributes(evidence.subject_tpmt_public)
    assert attrs.never_extractable is False and attrs.extractable is True

    result = KeyBindingVerifier().appraise(evidence, expected_nonce=_NONCE, policy=_POLICY)
    assert not result.accepted
    assert any("never-extractable" in e or "extractable" in e for e in result.errors)


def test_forged_proof_of_possession_is_rejected():
    """PoP by a key other than the certified one must fail (cnf mismatch)."""
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    evidence = attester.produce(_NONCE)

    attacker = ec.generate_private_key(ec.SECP256R1())
    forged = dataclasses.replace(evidence, pop_signature=attacker.sign(_NONCE, ec.ECDSA(hashes.SHA256())))

    result = KeyBindingVerifier().appraise(forged, expected_nonce=_NONCE, policy=_POLICY)
    assert not result.accepted
    assert "proof-of-possession" in result.errors[0]


def test_fixedparent_without_fixedtpm_is_extractable():
    """A key that blocks re-parenting but is NOT TPM-bound is still exfiltratable.

    fixedParent set + fixedTPM clear: the private blob can leave with a duplicable
    parent, so it MUST be reported extractable / not never-extractable, and the
    strict default policy must reject it.
    """
    from attester import FIXEDPARENT, SENSITIVEDATAORIGIN, SIGN_ENCRYPT, USERWITHAUTH

    attrs_bits = FIXEDPARENT | SENSITIVEDATAORIGIN | USERWITHAUTH | SIGN_ENCRYPT  # no FIXEDTPM
    attester = SyntheticKeyBindingAttester.generate(attrs_bits)
    evidence = attester.produce(_NONCE)

    attrs = derive_key_attributes(evidence.subject_tpmt_public)
    assert attrs.extractable is True
    assert attrs.never_extractable is False

    result = KeyBindingVerifier().appraise(evidence, expected_nonce=_NONCE, policy=_POLICY)
    assert not result.accepted


def test_out_of_range_nonce_returns_result_not_exception():
    """A misconfigured (too short/long) nonce yields a VerifyResult, never a crash."""
    from libattest.types import EarStatus

    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    verifier = KeyBindingVerifier()
    for bad_nonce in (b"7bytes!", b"x" * 65):  # EATNonce range is 8..64 bytes
        result = verifier.appraise(attester.produce(bad_nonce), expected_nonce=bad_nonce, policy=_POLICY)
        assert not result.accepted
        assert result.status == EarStatus.unknown


def _run_all() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for test in tests:
        test()
        print(f"  ok  {test.__name__}")
    print(f"\n{len(tests)} checks passed.")


if __name__ == "__main__":
    _run_all()
