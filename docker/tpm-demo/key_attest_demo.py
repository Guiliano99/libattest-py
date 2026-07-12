# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Readable TPM credential-activation demo on the live TPM.

The v5 key-attestation mechanism roots trust in ``TPM2_MakeCredential`` /
``TPM2_ActivateCredential``: the verifier wraps a fresh single-use ``seed`` to
``(EK, AK Name)``, and only a TPM that holds both the EK and the named AK can
recover it.  This script plays that core round-trip end to end:

1. Device provisions an EK and an AK (so a real TPM is present).
2. Verifier runs software ``TPM2_MakeCredential`` over ``(ekPublic, akName)`` →
   ``(encSeed, encSecret)``, retaining the ``seed``
   (:func:`libattest.verifier.verify_bridge.make_credential_challenge`).
3. Device runs ``TPM2_ActivateCredential`` and recovers the ``seed`` — only a
   TPM holding both the EK and the named AK can
   (:meth:`libattest.attester.tpm_client.TpmClient.recover_seed`).
4. The demo checks the recovered seed equals the verifier's retained seed.

The remaining legs of the full flow (``TPM2_Certify`` of the subject key,
``Esys_Sign`` of ``H(seed)`` → ``KeyAttestEvidence``, and the verifier's checks
2-8) require a tpm2-openssl subject key plus an AK certificate chain, and are
exercised by the remote-attest-e2e docker stack.

Drives a real TPM through :class:`libattest.attester.tpm_client.TpmClient`
(tpm2-pytss); the ``TCTI`` env var selects the TPM (``mssim:`` in the bundled
docker stack, in-process ``libtpms:`` locally).  See ``docker/tpm-demo/README.md``.
"""

from __future__ import annotations

import os

from libattest.attester.tpm_client import TpmClient
from libattest.verifier.verify_bridge import make_credential_challenge

_DEFAULT_TCTI = "libtpms:"


def run_demo(tcti: str | None = None) -> bool:
    """Run the credential-activation seed-recovery round-trip against a TPM.

    Returns ``True`` iff the device TPM recovers exactly the seed the verifier
    wrapped for ``(EK, AK Name)``.
    """
    resolved_tcti = tcti or os.environ.get("TCTI", _DEFAULT_TCTI)

    with TpmClient(tcti=resolved_tcti) as tpm:
        tpm.provision_ek()
        _ak_public, ak_name = tpm.provision_ak()
        ek_public = bytes(tpm.ek_public.marshal())

        # Verifier side: fresh single-use seed wrapped to (EK, AK Name).
        session_id, seed, enc_seed, enc_secret = make_credential_challenge(bytes(ak_name), ek_public)

        # Device side: recover the seed via TPM2_ActivateCredential.
        recovered = tpm.recover_seed(enc_secret=enc_secret, enc_seed=enc_seed)

    ok = recovered == seed
    print("TPM credential-activation (v5 key-attestation core) demo")
    print(f"TCTI:              {resolved_tcti}")
    print(f"sessionId:         {session_id}")
    print(f"activation seed:   {seed.hex()}")
    print(f"recovered == seed: {ok}")
    print(f"Verdict:           {'ACCEPT' if ok else 'REJECT'}")
    return ok


def main() -> None:
    """Run the credential-activation demo as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
