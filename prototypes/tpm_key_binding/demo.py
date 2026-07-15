# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: T201

"""End-to-end demo: TPM key-binding Evidence → Verifier → signed EAR.

Runs the software (synthetic) path by default — no TPM needed. Set the
``LIBATTEST_TCTI`` environment variable (e.g. ``mssim:host=127.0.0.1,port=2321``)
to also run the real-TPM path against a live TPM/simulator.

    python demo.py
    LIBATTEST_TCTI=mssim:host=127.0.0.1,port=2321 python demo.py
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from attester import STRONG_SUBJECT_ATTRS, WEAK_SUBJECT_ATTRS, SyntheticKeyBindingAttester  # noqa: E402
from key_attributes import KeyBindingPolicy  # noqa: E402
from verifier import KeyBindingVerifier  # noqa: E402

from libattest.formats.eat_ear.cwt_jwt import ear_is_affirming, verify_ear_jwt  # noqa: E402

# A real deployment fetches this from the Verifier; here it is a fixed 32 bytes.
NONCE = os.urandom(32)
POLICY = KeyBindingPolicy()  # require never-extractable + local, forbid extractable


def _pretty(ear_jwt: str) -> str:
    part = ear_jwt.split(".")[1]
    payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    return json.dumps(payload, indent=2)


def _rule(title: str) -> None:
    print(f"\n{'─' * 70}\n{title}\n{'─' * 70}")


def run_synthetic() -> None:
    """Run the offline synthetic key-binding demonstration."""
    _rule("1) Software path (no TPM) — strong Subject Key, strict policy")
    attester = SyntheticKeyBindingAttester.generate(STRONG_SUBJECT_ATTRS)
    verifier = KeyBindingVerifier()

    evidence = attester.produce(NONCE)
    print(
        f"evidence: TcgAttestCertify DER = {len(evidence.certify_der())} bytes "
        f"(OID 2.23.133.20.1); TPMT_PUBLIC = {len(evidence.subject_tpmt_public)} bytes"
    )

    result = verifier.appraise(evidence, expected_nonce=NONCE, policy=POLICY)
    print(f"verdict : {result.status.value}")
    assert result.accepted, result.errors

    ear = result.payload
    print(
        f"EAR sig : {'verified' if verify_ear_jwt(ear, verifier.ear_verification_key()) else 'FAILED'} "
        f"under the Verifier's public key"
    )
    print(f"RP read : ear_is_affirming(ear) = {ear_is_affirming(ear)}  (via the repo helper)")
    print("EAR payload:")
    print(_pretty(ear))

    _rule("2) Software path — weak (extractable) Subject Key must be REJECTED")
    weak = SyntheticKeyBindingAttester.generate(WEAK_SUBJECT_ATTRS)
    rejected = verifier.appraise(weak.produce(NONCE), expected_nonce=NONCE, policy=POLICY)
    print(f"verdict : {rejected.status.value}")
    for err in rejected.errors:
        print(f"  reason: {err}")
    assert not rejected.accepted


def run_real_tpm(tcti: str) -> None:
    """Run the key-binding flow against a live TPM at *tcti*."""
    _rule(f"3) Real-TPM path via TCTI {tcti!r}")
    try:
        from attester import TpmKeyBindingAttester

        from libattest.attester.tpm_client import TpmClient

        with TpmClient(tcti=tcti, ak_family="ecc", hash_alg="sha256") as tpm:
            tpm.provision_ak()
            evidence = TpmKeyBindingAttester(tpm).produce(NONCE)
        verifier = KeyBindingVerifier()
        result = verifier.appraise(evidence, expected_nonce=NONCE, policy=POLICY)
        print(f"verdict : {result.status.value}")
        if result.accepted:
            print("EAR payload:")
            print(_pretty(result.payload))
        else:
            for err in result.errors:
                print(f"  reason: {err}")
    except Exception as exc:  # noqa: BLE001 — demo: report and continue
        print(f"real-TPM path unavailable: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    run_synthetic()
    tcti = os.environ.get("LIBATTEST_TCTI")
    if tcti:
        run_real_tpm(tcti)
    else:
        print("\n(Set LIBATTEST_TCTI=mssim:host=...,port=2321 to also run the real-TPM path.)")
