# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Readable TPM key-attestation (v5 ``KeyAttestPoP``) demo on the live TPM.

Plays the v5 challenge-bound proof-of-possession flow end to end:

1. Device provisions an EK and an AK (so a real TPM is present).
2. Verifier generates a fresh single-use ``seed`` and runs
   ``TPM2_MakeCredential`` bound to ``(EK, AK Name)`` — the ``encSeed`` /
   ``encSecret`` blobs that ride in ``KeyAttestResp``.
3. Device runs ``TPM2_ActivateCredential`` and recovers ``seed`` — only a TPM
   that holds both the EK and the named AK can.
4. The requested key signs the recovered ``seed`` → ``KeyAttestPoP``.
5. The CA/RA verifies the PoP signature over the ``seed`` it stored.

Drives a real TPM through :class:`libattest.attester.tpm_client.TpmClient`
(tpm2-pytss); the ``TCTI`` env var selects the TPM (``mssim:`` in the bundled
docker stack, in-process ``libtpms:`` locally).  See ``docker/tpm-demo/README.md``.
"""

from __future__ import annotations

import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from libattest.attester.tpm_client import TpmClient
from libattest.formats.key_attest_pop import compute_key_attest_pop, encode_to_der
from libattest.verifier.reference import AcceptAllReferenceHandler
from libattest.verifier.tpm.tpm_keyattest_verifier import TpmKeyAttestVerifier

_DEFAULT_TCTI = "libtpms:"


def run_demo(tcti: str | None = None) -> bool:
    """Run the v5 credential-activation + KeyAttestPoP flow against a TPM.

    Returns ``True`` iff the seed is recovered and the PoP verifies.
    """
    resolved_tcti = tcti or os.environ.get("TCTI", _DEFAULT_TCTI)

    # The requested key being certified — signs the recovered seed (KeyAttestPoP).
    requested_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    spki_der = requested_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with TpmClient(tcti=resolved_tcti) as tpm:
        tpm.provision_ek()
        tpm.provision_ak()
        # Verifier side: fresh activation secret, wrapped to (EK, AK Name).
        seed = secrets.token_bytes(32)
        cred_blob, enc_secret = tpm.make_credential_challenge(seed)
        # Device side: recover the seed via TPM2_ActivateCredential.
        recovered = tpm.activate_credential(cred_blob, enc_secret)

    # Device signs the recovered seed → KeyAttestPoP; the CA/RA verifies it.
    pop = compute_key_attest_pop(requested_key, recovered)
    verifier = TpmKeyAttestVerifier(reference_handler=AcceptAllReferenceHandler())
    result = verifier.verify_activation_pop(
        seed=seed,
        spki_der=spki_der,
        pop_der=encode_to_der(pop),
    )

    print("TPM key attestation (v5 KeyAttestPoP) demo")
    print(f"TCTI:              {resolved_tcti}")
    print(f"activation seed:   {seed.hex()}")
    print(f"recovered == seed: {recovered == seed}")
    print(f"Verdict:           {'ACCEPT' if result.accepted else 'REJECT'}")
    print(f"Detail:            {result.payload if result.accepted else result.errors}")
    return result.accepted and recovered == seed


def main() -> None:
    """Run the key-attestation demo as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
