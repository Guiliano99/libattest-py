# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM attestation formats."""

from libattest.formats.tpm.pcr_selection import (
    TPM_PCR_SELECTION_OID_DEFAULT,
    TPM_PCR_SELECTION_OID_ENV,
    TpmAttestationParamsASN1,
    decode_tpm_attestation_params,
    encode_tpm_attestation_params,
    extract_pcr_selection_from_response_params,
    make_pcr_selection_response_param,
    resolve_tpm_pcr_selection_oid,
)
from libattest.formats.tpm.tcg import (
    TcgAttestCertify,
    id_tcg_attest_certify,
    prepare_tcg_attest_certify,
)
from libattest.formats.tpm.tpm_name import compute_tpm_name
from libattest.formats.tpm.tpms_attest import (
    extract_certify_name,
    extract_qualifying_data,
    extract_quote_info,
)

__all__ = [
    "TPM_PCR_SELECTION_OID_DEFAULT",
    "TPM_PCR_SELECTION_OID_ENV",
    "TcgAttestCertify",
    "TpmAttestationParamsASN1",
    "compute_tpm_name",
    "decode_tpm_attestation_params",
    "encode_tpm_attestation_params",
    "extract_certify_name",
    "extract_pcr_selection_from_response_params",
    "extract_qualifying_data",
    "extract_quote_info",
    "id_tcg_attest_certify",
    "make_pcr_selection_response_param",
    "prepare_tcg_attest_certify",
    "resolve_tpm_pcr_selection_oid",
]
