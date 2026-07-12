# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Quick manual check: run a real TPM2_Certify and print what it returns.

Start the simulator, then run this script against it:

    docker compose -f docker/tpm-demo/docker-compose.yml up -d tpmsim
    docker compose -f docker/tpm-demo/docker-compose.yml run --rm client python docker/tpm-demo/quick_test.py

Provisions an EK and an AK, creates a fresh subject key, certifies it with
the AK (the actual ``TPM2_Certify`` command via
:meth:`~libattest.attester.tpm_client.TpmClient.ectx`), and prints the parsed
result — including ``TPMS_ATTEST.type``, which reads ``0x8017
(ATTEST_CERTIFY)`` for a real ``TPM2_Certify`` response.

Bypasses :meth:`TpmClient.certify`'s TSS2-PEM subject-key wrapper (that route
needs a persisted SRK at a fixed handle, which nothing in this repo sets up)
and instead mirrors the real-TPM subject-key + certify pattern already
exercised in ``prototypes/tpm_key_binding/attester.py``
(:meth:`TpmKeyBindingAttester.produce`), feeding the raw result through the
existing :meth:`TpmClient.parse_certify` to get a friendly summary.
"""

from __future__ import annotations

import os
import secrets

from tpm2_pytss import ESYS_TR, TPM2_ALG, TPM2B_PUBLIC, TPMA_OBJECT, TPMT_PUBLIC, TPMT_SIG_SCHEME

from libattest.attester.tpm_client import TpmClient

_DEFAULT_TCTI = "libtpms:"

#: A TPM-resident, non-duplicable, unrestricted signing key (TPM 2.0 Part 2 §8.3).
_SUBJECT_ATTRS = (
    TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN
    | TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.SIGN_ENCRYPT
)


def run_demo(tcti: str | None = None) -> bool:
    """Provision EK+AK, certify a fresh subject key, print the TPM2_Certify result.

    Returns ``True`` iff the parsed response really is a certify statement
    (``TPMS_ATTEST.type == TPM_ST_ATTEST_CERTIFY``).
    """
    resolved_tcti = tcti or os.environ.get("TCTI", _DEFAULT_TCTI)

    with TpmClient(tcti=resolved_tcti) as tpm:
        tpm.provision_ek()
        tpm.provision_ak()

        ectx = tpm.ectx
        subject_template = TPMT_PUBLIC.parse(
            alg="ecc256:ecdsa-sha256:null",
            objectAttributes=_SUBJECT_ATTRS,
            nameAlg=TPM2_ALG.SHA256,
        )
        subject_handle, subject_public, _, _, _ = ectx.create_primary(
            in_sensitive=None,
            in_public=TPM2B_PUBLIC(publicArea=subject_template),
            primary_handle=ESYS_TR.OWNER,
        )
        try:
            nonce = secrets.token_bytes(20)
            # This is the actual TPM2_Certify command.
            attest, signature = ectx.certify(
                subject_handle,
                tpm.ak_handle,
                nonce,
                TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
            )
        finally:
            ectx.flush_context(subject_handle)

        result = tpm.parse_certify(attest, signature, subject_public)

    print("TPM2_Certify quick test")
    print(f"TCTI: {resolved_tcti}")
    print(result.summary())
    return result.attest_type == 0x8017


def main() -> None:
    """Run the quick certify test as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
