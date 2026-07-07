# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""OID lookup for the TPM platform-attestation PCR-selection profile.

``resolve_tpm_pcr_selection_oid`` identifies the TPM PCR-selection
``NonceRequestTypeInfo.type``/``NonceResponseTypeInfo.type`` used to route
respInfo through :mod:`libattest.formats.respinfo`'s registry, alongside
``id_tcg_attest_quote``.  The value encoding itself is
:mod:`libattest.formats.tpm.quote_profile` (``TPM20QuoteReqInfo``/
``TPM20QuoteRespInfo``).
"""

from __future__ import annotations

from libattest.formats._oid_json import resolve_env_oid

TPM_PCR_SELECTION_OID_DEFAULT: str = "1.3.6.1.4.1.99999.3"
TPM_PCR_SELECTION_OID_ENV: str = "TPM_PCR_SELECTION_OID"


def resolve_tpm_pcr_selection_oid() -> str:
    """Return the configured PCR-selection OID."""
    return resolve_env_oid(TPM_PCR_SELECTION_OID_ENV, TPM_PCR_SELECTION_OID_DEFAULT)


__all__ = [
    "TPM_PCR_SELECTION_OID_DEFAULT",
    "TPM_PCR_SELECTION_OID_ENV",
    "resolve_tpm_pcr_selection_oid",
]
