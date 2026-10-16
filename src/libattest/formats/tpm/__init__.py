# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""TPM attestation formats.

All TPM wire structures live in :mod:`structures` (PCR quote, TCG certify, and the
IAK/LDevID key-attestation profiles), sharing the primitives in :mod:`asn1_types`;
the object-attribute floor parser is :mod:`attributes`.  These three modules are
pure pyasn1 and eagerly re-exported here.

The ``tpm2-pytss``-backed helpers (``tpms_attest`` and the certify-name /
TPMT_SIGNATURE helpers) stay behind the PEP 562 lazy boundary below, so importing
``libattest.formats.tpm`` never pulls the native binding — the MockCA image has no
``tpm2-pytss`` and only wants the pyasn1 codecs.
"""

from libattest.formats.tpm.asn1_types import (
    PCRIndex,
    Tpm2bEncryptedSecret,
    Tpm2bIdObject,
    Tpm2bPublic,
    TPMAlgId,
    TpmsAttest,
    TpmtPublic,
    TpmtSignature,
)
from libattest.formats.tpm.attributes import (
    TpmaObject,
    enforce_iak_floor,
    enforce_ldevid_floor,
    read_object_attributes,
    strip_tpm2b_prefix,
)
from libattest.formats.tpm.structures import (
    IakKeyAttestEvidence,
    IakKeyAttestReqInfo,
    IakKeyAttestRespInfo,
    LdevidKeyAttestEvidence,
    LdevidKeyAttestReqInfo,
    LdevidKeyAttestRespInfo,
    TcgAttestCertify,
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    decode_iak_key_attest_evidence,
    decode_iak_key_attest_req_info,
    decode_iak_key_attest_resp_info,
    decode_ldevid_key_attest_evidence,
    decode_ldevid_key_attest_req_info,
    decode_ldevid_key_attest_resp_info,
    decode_tcg_attest_certify,
    decode_tpm20_quote_req_info,
    decode_tpm20_quote_req_info_asn1,
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_req_info,
    encode_tpm20_quote_resp_info,
    iak_key_attest_req_info_to_json,
    id_tcg_attest_certify,
    id_tcg_attest_quote,
    id_tpm20_quote_req,
    id_tpm20_quote_res,
    id_tpm_iak_key_attest_request,
    id_tpm_iak_key_attest_response,
    id_tpm_iak_key_attest_statement,
    id_tpm_key_attest_req,
    id_tpm_ldevid_key_attest_request,
    id_tpm_ldevid_key_attest_response,
    id_tpm_ldevid_key_attest_statement,
    prepare_iak_key_attest_evidence,
    prepare_iak_key_attest_req_info,
    prepare_iak_key_attest_resp_info,
    prepare_ldevid_key_attest_evidence,
    prepare_ldevid_key_attest_req_info,
    prepare_ldevid_key_attest_resp_info,
    prepare_tcg_attest_certify,
    tpm20_quote_request_info,
    tpm20_quote_resp_info_from_response_info,
    tpm20_quote_response_info,
)

# ``tpms_attest`` is the only TPM-format module that hard-depends on the native
# ``tpm2-pytss`` binding (it sources the TCG algorithm ids and the ``TPMS_ATTEST``
# unmarshaller from it).  The pyasn1-only codecs above (structures / asn1_types /
# attributes) carry the nonce-negotiation + respInfo helpers the MockCA needs, and
# the MockCA image deliberately does NOT install ``tpm2-pytss``.
#
# Re-exporting ``tpms_attest`` eagerly here would therefore make *importing*
# ``libattest.formats.tpm`` fail on a tpm2-pytss-less host (the MockCA), even for
# callers that only want the pyasn1 codecs.  Expose the tpms_attest symbols lazily
# via PEP 562 ``__getattr__`` instead: the names stay importable and resolve the
# native dependency only when first accessed — exactly where ``tpm2-pytss`` is
# present (the verifier).
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
        "TPM_ST_ATTEST_CERTIFY",
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
    # key templates + default object-attribute sets (tpm2-pytss-requiring)
    "DEFAULT_AK_ATTRS": "libattest.formats.tpm.tpm_utils",
    "DEFAULT_DEVID_ATTRS": "libattest.formats.tpm.tpm_utils",
    "DEFAULT_EK_ATTRS": "libattest.formats.tpm.tpm_utils",
    "DEFAULT_SRK_ATTRS": "libattest.formats.tpm.tpm_utils",
    "EK_AUTH_POLICY_SHA256": "libattest.formats.tpm.tpm_utils",
    "HASH_ALG_IDS": "libattest.formats.tpm.tpm_utils",
    "ak_template": "libattest.formats.tpm.tpm_utils",
    "devid_template": "libattest.formats.tpm.tpm_utils",
    "ek_template": "libattest.formats.tpm.tpm_utils",
    "iak_template": "libattest.formats.tpm.tpm_utils",
    "srk_template": "libattest.formats.tpm.tpm_utils",
}


def __getattr__(name: str):
    """Lazily resolve TPM helpers that pull native or heavy deps (PEP 562)."""
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


# The lazy pytss-backed names below resolve through the PEP 562 ``__getattr__``
# above rather than module globals, which pylint's static ``__all__`` check cannot
# follow. They are importable at runtime (that is what the lazy export is for).
# pylint: disable=undefined-all-variable
__all__ = [
    # lazy pytss-backed (tpms_attest)
    "TPM_ALG_ECDSA",
    "TPM_ALG_RSAPSS",
    "TPM_ALG_RSASSA",
    "TPM_ALG_SHA1",
    "TPM_ALG_SHA256",
    "TPM_ALG_SHA384",
    "TPM_ALG_SHA512",
    "TPM_GENERATED_VALUE",
    "TPM_ST_ATTEST_CERTIFY",
    "TPM_ST_ATTEST_QUOTE",
    "ParsedAttest",
    "TpmQuoteSignatureEvidence",
    "compute_tpm_name",
    "extract_certify_name",
    "extract_qualifying_data",
    "extract_quote_info",
    "parse_tpms_attest",
    "pcr_indices_to_mask",
    "pcr_mask_to_indices",
    "verify_tpm_signature",
    # key templates + default object-attribute sets (lazy pytss-backed, tpm_utils)
    "DEFAULT_AK_ATTRS",
    "DEFAULT_DEVID_ATTRS",
    "DEFAULT_EK_ATTRS",
    "DEFAULT_SRK_ATTRS",
    "EK_AUTH_POLICY_SHA256",
    "HASH_ALG_IDS",
    "ak_template",
    "devid_template",
    "ek_template",
    "iak_template",
    "srk_template",
    # primitives (asn1_types)
    "PCRIndex",
    "TPMAlgId",
    "Tpm2bEncryptedSecret",
    "Tpm2bIdObject",
    "Tpm2bPublic",
    "TpmsAttest",
    "TpmtPublic",
    "TpmtSignature",
    # object-attribute floor (attributes)
    "TpmaObject",
    "enforce_iak_floor",
    "enforce_ldevid_floor",
    "read_object_attributes",
    "strip_tpm2b_prefix",
    # structures + OIDs + codecs (structures)
    "IakKeyAttestEvidence",
    "IakKeyAttestReqInfo",
    "IakKeyAttestRespInfo",
    "LdevidKeyAttestEvidence",
    "LdevidKeyAttestReqInfo",
    "LdevidKeyAttestRespInfo",
    "TPM20QuoteReqInfoASN1",
    "TPM20QuoteRespInfoASN1",
    "TcgAttestCertify",
    "decode_iak_key_attest_evidence",
    "decode_iak_key_attest_req_info",
    "decode_iak_key_attest_resp_info",
    "decode_ldevid_key_attest_evidence",
    "decode_ldevid_key_attest_req_info",
    "decode_ldevid_key_attest_resp_info",
    "decode_tcg_attest_certify",
    "decode_tpm20_quote_req_info",
    "decode_tpm20_quote_req_info_asn1",
    "decode_tpm20_quote_resp_info",
    "encode_tpm20_quote_req_info",
    "encode_tpm20_quote_resp_info",
    "iak_key_attest_req_info_to_json",
    "id_tcg_attest_certify",
    "id_tcg_attest_quote",
    "id_tpm20_quote_req",
    "id_tpm_key_attest_req",
    "id_tpm20_quote_res",
    "id_tpm_iak_key_attest_request",
    "id_tpm_iak_key_attest_response",
    "id_tpm_iak_key_attest_statement",
    "id_tpm_ldevid_key_attest_request",
    "id_tpm_ldevid_key_attest_response",
    "id_tpm_ldevid_key_attest_statement",
    "prepare_iak_key_attest_evidence",
    "prepare_iak_key_attest_req_info",
    "prepare_iak_key_attest_resp_info",
    "prepare_ldevid_key_attest_evidence",
    "prepare_ldevid_key_attest_req_info",
    "prepare_ldevid_key_attest_resp_info",
    "prepare_tcg_attest_certify",
    "tpm20_quote_request_info",
    "tpm20_quote_resp_info_from_response_info",
    "tpm20_quote_response_info",
]
