# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM attestation formats."""

from libattest.formats.tpm.pcr_selection import (
    TPM_PCR_SELECTION_OID_DEFAULT,
    TPM_PCR_SELECTION_OID_ENV,
    resolve_tpm_pcr_selection_oid,
)
from libattest.formats.tpm.quote_profile import (
    PCRIndex,
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    TPMAlgId,
    decode_tpm20_quote_req_info,
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_req_info,
    encode_tpm20_quote_resp_info,
    id_tpm20_quote_req,
    id_tpm20_quote_res,
    tpm20_quote_request_info,
    tpm20_quote_resp_info_from_response_info,
    tpm20_quote_response_info,
)
from libattest.formats.tpm.tcg import (
    TcgAttestCertify,
    decode_tcg_attest_certify,
    id_tcg_attest_certify,
    id_tcg_attest_quote,
    prepare_tcg_attest_certify,
)

# ``tpms_attest`` is the only TPM-format module that hard-depends on the native
# ``tpm2-pytss`` binding (it sources the TCG algorithm ids and the ``TPMS_ATTEST``
# unmarshaller from it).  The pyasn1-only codecs above (pcr_selection /
# quote_profile / tcg) carry the nonce-negotiation + respInfo helpers the MockCA
# needs, and the MockCA image deliberately does NOT install ``tpm2-pytss``.
#
# Re-exporting ``tpms_attest`` eagerly here would therefore make *importing*
# ``libattest.formats.tpm`` fail on a tpm2-pytss-less host (the MockCA), even
# for callers that only want the pyasn1 codecs.  Expose the tpms_attest symbols
# lazily via PEP 562 ``__getattr__`` instead: the names stay importable
# (``from libattest.formats.tpm import parse_tpms_attest``) and resolve the
# native dependency only when first accessed — exactly where ``tpm2-pytss`` is
# present (the verifier).
# Symbols served lazily from ``tpms_attest`` (which loads ``tpm2-pytss`` for the
# typed unmarshal; the ``extract_*`` / ``pcr_*`` parsers themselves are pure
# struct, but they live in the same tpm2-pytss-importing module).
_LAZY_TPMS_ATTEST_EXPORTS = frozenset(
    {
        "TPM_ALG_ECDSA",
        "TPM_ALG_RSAPSS",
        "TPM_ALG_RSASSA",
        "TPM_ALG_SHA1",
        "TPM_ALG_SHA256",
        "TPM_ALG_SHA384",
        "TPM_ALG_SHA512",
        "TPM_GENERATED_VALUE",
        "TPM_ST_ATTEST_QUOTE",
        "ParsedAttest",
        "TpmQuoteSignatureEvidence",
        "parse_tpms_attest",
        "pcr_indices_to_mask",
        "pcr_mask_to_indices",
        "extract_qualifying_data",
        "extract_certify_name",
        "extract_quote_info",
    }
)

# Symbols served lazily from their own tpm2-pytss-free modules.  Exposed lazily
# too so this package's import surface stays uniform (and never pulls
# ``cryptography`` until a TPM-signature/name helper is actually used).
_LAZY_MODULE_EXPORTS = {
    "compute_tpm_name": "libattest.formats.tpm.tpm_name",
    "verify_tpm_signature": "libattest.formats.tpm.tpm_signature",
}


def __getattr__(name: str):
    """Lazily resolve TPM helpers that pull native or heavy deps (PEP 562).

    Keeps ``libattest.formats.tpm`` importable without ``tpm2-pytss`` while
    still exposing the native-backed TPMS_ATTEST helpers (and the certify
    name / TPMT_SIGNATURE helpers) on first access.
    """
    if name in _LAZY_TPMS_ATTEST_EXPORTS:
        from libattest.formats.tpm import tpms_attest  # noqa: PLC0415

        return getattr(tpms_attest, name)
    if name in _LAZY_MODULE_EXPORTS:
        import importlib  # noqa: PLC0415

        module = importlib.import_module(_LAZY_MODULE_EXPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Include the lazy exports in ``dir()`` for discoverability."""
    return sorted(set(globals()) | _LAZY_TPMS_ATTEST_EXPORTS | set(_LAZY_MODULE_EXPORTS))


__all__ = [
    "TPM_ALG_ECDSA",
    "TPM_ALG_RSAPSS",
    "TPM_ALG_RSASSA",
    "TPM_ALG_SHA1",
    "TPM_ALG_SHA256",
    "TPM_ALG_SHA384",
    "TPM_ALG_SHA512",
    "TPM_GENERATED_VALUE",
    "TPM20QuoteReqInfoASN1",
    "TPM20QuoteRespInfoASN1",
    "TPM_PCR_SELECTION_OID_DEFAULT",
    "TPM_PCR_SELECTION_OID_ENV",
    "TPM_ST_ATTEST_QUOTE",
    "TPMAlgId",
    "PCRIndex",
    "TcgAttestCertify",
    "TpmQuoteSignatureEvidence",
    "compute_tpm_name",
    "decode_tcg_attest_certify",
    "decode_tpm20_quote_req_info",
    "decode_tpm20_quote_resp_info",
    "encode_tpm20_quote_req_info",
    "encode_tpm20_quote_resp_info",
    "extract_certify_name",
    "extract_qualifying_data",
    "extract_quote_info",
    "id_tcg_attest_certify",
    "id_tcg_attest_quote",
    "id_tpm20_quote_req",
    "id_tpm20_quote_res",
    "ParsedAttest",
    "parse_tpms_attest",
    "pcr_indices_to_mask",
    "pcr_mask_to_indices",
    "prepare_tcg_attest_certify",
    "resolve_tpm_pcr_selection_oid",
    "tpm20_quote_request_info",
    "tpm20_quote_resp_info_from_response_info",
    "tpm20_quote_response_info",
    "verify_tpm_signature",
]
