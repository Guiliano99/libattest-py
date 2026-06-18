# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Readable TPM2 platform-attestation demo.

Provisions an EK + AK on the TPM, runs a real ``TPM2_Quote`` over the default
PCR selection with a verifier nonce, and appraises it end-to-end with
libattest's :class:`TpmPlatformVerifier` (structural + freshness + AK signature
+ PCR-selection binding + reference digest).

Drives a real TPM through :class:`libattest.attester.tpm_client.TpmClient`
(tpm2-pytss).  In the bundled ``docker/tpm-demo`` stack the ``TCTI`` env var
points at the IBM software TPM (``mssim:host=tpmsim,port=2321``); locally it
falls back to the in-process ``libtpms:`` TCTI.  See ``docker/tpm-demo/README.md``.
"""

from __future__ import annotations

import hashlib
import os
import secrets

from libattest.attester.tpm_client import TpmClient
from libattest.formats.tpm import TPM_ALG_SHA256
from libattest.verifier.reference import AcceptAllReferenceHandler
from libattest.verifier.tpm.reference_values import PcrReferenceValues
from libattest.verifier.tpm.tpm_platform_verifier import TpmPlatformVerifier

_DEFAULT_TCTI = "libtpms:"
_PCR_SELECTION = "sha256:0,1,2,3,4"
# pcrDigest over 5 zeroed SHA-256 PCRs — the simulator reset state for PCRs 0-4.
_ZERO_PCR_DIGEST_HEX = hashlib.sha256(b"\x00" * 32 * 5).hexdigest()


def run_demo(
    tcti: str | None = None,
    pcr_selection: str = _PCR_SELECTION,
) -> bool:
    """Provision a TPM, quote it, and appraise the quote with libattest.

    Returns ``True`` iff the verifier accepts the quote.
    """
    resolved_tcti = tcti or os.environ.get("TCTI", _DEFAULT_TCTI)
    pcrs = [int(idx) for idx in pcr_selection.split(":", 1)[1].split(",")]

    with TpmClient(tcti=resolved_tcti) as tpm:
        tpm.provision_ek()
        tpm.provision_ak()
        nonce = secrets.token_bytes(20)  # the verifier's qualifyingData
        qr = tpm.quote(nonce, pcr_selection=pcr_selection)
        evidence = qr.to_evidence(tpm.ak_public_pem())

    reference = PcrReferenceValues(
        expected_pcr_digest_hex=_ZERO_PCR_DIGEST_HEX,
        description="software TPM reset state, PCRs 0-4",
    )
    verifier = TpmPlatformVerifier(reference_handler=AcceptAllReferenceHandler())
    result = verifier.appraise_quote(
        evidence,
        expected_nonce=nonce,
        reference=reference,
        expected_pcrs=pcrs,
        expected_hash_alg_id=TPM_ALG_SHA256,
    )

    print("TPM2 platform attestation demo")
    print(f"TCTI:          {resolved_tcti}")
    print(f"PCR selection: {pcr_selection}")
    print(f"quoted digest: {qr.pcr_digest.hex()}")
    print(f"sigAlg/hash:   {qr.sig_alg:#06x} / {qr.sig_hash:#06x}")
    print(f"Verdict:       {'ACCEPT' if result.accepted else 'REJECT'}")
    print(f"Detail:        {result.payload if result.accepted else result.errors}")
    return result.accepted


def main() -> None:
    """Run the platform-attestation demo as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
