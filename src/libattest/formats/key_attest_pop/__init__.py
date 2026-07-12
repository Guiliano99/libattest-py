# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Typed ASN.1 structures + JSON adapters for the v5 TPM key-attestation flow."""

from libattest.formats.key_attest_pop.structures import (
    DEFAULT_KEY_ATTEST_EVIDENCE_OID,
    ID_KEY_ATTEST_EVIDENCE,
    ID_KEY_ATTEST_EVIDENCE_DOTTED,
    KEY_ATTEST_EVIDENCE_OID_ENV,
    EkCertChain,
    KeyAttestChall,
    KeyAttestEvidence,
    KeyAttestResp,
    decode_key_attest_chall,
    decode_key_attest_evidence,
    decode_key_attest_resp,
    encode_to_der,
    key_attest_chall_to_json,
    key_attest_resp_from_json,
    prepare_key_attest_chall,
    prepare_key_attest_evidence,
    prepare_key_attest_resp,
    resolve_key_attest_evidence_oid,
)

__all__ = [
    "DEFAULT_KEY_ATTEST_EVIDENCE_OID",
    "ID_KEY_ATTEST_EVIDENCE",
    "ID_KEY_ATTEST_EVIDENCE_DOTTED",
    "KEY_ATTEST_EVIDENCE_OID_ENV",
    "EkCertChain",
    "KeyAttestChall",
    "KeyAttestEvidence",
    "KeyAttestResp",
    "decode_key_attest_chall",
    "decode_key_attest_evidence",
    "decode_key_attest_resp",
    "encode_to_der",
    "key_attest_chall_to_json",
    "key_attest_resp_from_json",
    "prepare_key_attest_chall",
    "prepare_key_attest_evidence",
    "prepare_key_attest_resp",
    "resolve_key_attest_evidence_oid",
]
