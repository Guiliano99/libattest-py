# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Quick manual check: run a real TPM2_CertifyCreation and print what it returns.

Start the simulator, then run this script against it:

    docker compose -f docker/tpm-demo/docker-compose.yml up -d tpmsim
    docker compose -f docker/tpm-demo/docker-compose.yml run --rm client \
      python docker/tpm-demo/quick_test_certify_creation.py

Sibling of ``quick_test.py`` (which exercises ``TPM2_Certify``): provisions an
EK and an AK, creates a fresh subject key (capturing the ``creationHash`` and
``creationTicket`` that ``TPM2_Create``/``TPM2_CreatePrimary`` produce), then
certifies its *creation* with the AK via the real ``TPM2_CertifyCreation``
command. Printed output shows ``TPMS_ATTEST.type == 0x801a
(ATTEST_CREATION)`` and the ``TPMS_CREATION_INFO`` union
(``objectName``/``creationHash``) — the concrete difference from
``TPM2_Certify``'s ``0x8017 (ATTEST_CERTIFY)`` / ``TPMS_CERTIFY_INFO``
(``name``/``qualifiedName``) that ``quick_test.py`` prints.

Not routed through ``TpmClient``: neither a ``certify_creation()`` method nor
a ``CertifyCreationResult`` exist in ``tpm_client.py`` (only ``TPM2_Certify``
is used anywhere in this repo). This script drives the raw ESAPI call
directly and unmarshals the response with tpm2-pytss's own
``TPMS_ATTEST.unmarshal`` for field access. There is no ready-made pretty
printer for this: tpm2-pytss's structs have no custom ``__str__`` (unmarshal
gives a plain object), and ``tpm2-tools``' ``tpm2_print`` (which would YAML-dump
it) isn't installed in this image — only tpm2-tss + tpm2-pytss are built (see
``Dockerfile.client``). So this prints the handful of relevant fields
directly, the same way ``CertifyResult.summary()``/``QuoteResult.summary()``
already do in ``tpm_client.py``.
"""

from __future__ import annotations

import os
import secrets

from tpm2_pytss import (
    ESYS_TR,
    TPM2_ALG,
    TPM2B_PUBLIC,
    TPMA_OBJECT,
    TPMS_ATTEST,
    TPMT_PUBLIC,
    TPMT_SIG_SCHEME,
)

from libattest.attester.tpm_client import TpmClient

_DEFAULT_TCTI = "libtpms:"

#: Same subject-key shape as quick_test.py's TPM2_Certify example.
_SUBJECT_ATTRS = (
    TPMA_OBJECT.FIXEDTPM
    | TPMA_OBJECT.FIXEDPARENT
    | TPMA_OBJECT.SENSITIVEDATAORIGIN
    | TPMA_OBJECT.USERWITHAUTH
    | TPMA_OBJECT.SIGN_ENCRYPT
)


def run_demo(tcti: str | None = None) -> bool:
    """Provision EK+AK, run TPM2_CertifyCreation over a fresh key, print the result.

    Returns ``True`` iff the parsed response really is a creation statement
    (``TPMS_ATTEST.type == TPM_ST_ATTEST_CREATION``).
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
        # TPM2_Create(Primary) is what produces the creationHash/creationTicket
        # that TPM2_CertifyCreation needs — TPM2_Certify never sees them.
        subject_handle, _, _, creation_hash, creation_ticket = ectx.create_primary(
            in_sensitive=None,
            in_public=TPM2B_PUBLIC(publicArea=subject_template),
            primary_handle=ESYS_TR.OWNER,
        )
        try:
            nonce = secrets.token_bytes(20)
            # This is the actual TPM2_CertifyCreation command.
            attest, _ = ectx.certify_creation(
                tpm.ak_handle,
                subject_handle,
                nonce,
                creation_hash,
                TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
                creation_ticket,
            )
        finally:
            ectx.flush_context(subject_handle)

    parsed, _ = TPMS_ATTEST.unmarshal(bytes(attest.attestationData))
    creation_info = parsed.attested.creation

    print("TPM2_CertifyCreation quick test")
    print(f"TCTI: {resolved_tcti}")
    print(f"magic           = {int(parsed.magic):#010x}")
    print(f"type            = {int(parsed.type):#06x} (ATTEST_CREATION)")
    print(f"nonce/extraData = {bytes(parsed.extraData).hex()}")
    print(f"qualifiedSigner = {bytes(parsed.qualifiedSigner).hex()}")
    print(f"objectName      = {bytes(creation_info.objectName).hex()}")
    print(f"creationHash    = {bytes(creation_info.creationHash).hex()}")
    return int(parsed.type) == 0x801A


def main() -> None:
    """Run the quick CertifyCreation test as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
