# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for OID-selected CMP nonce and attestation-statement payload mappings."""

from __future__ import annotations

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280

from libattest.formats.eareat_hpke import EVIDENCE_ENC_PARAMS_OID, resolve_evidence_enc_oid
from libattest.formats.key_attest_pop import (
    KeyAttestChall,
    KeyAttestEvidence,
    KeyAttestResp,
    resolve_key_attest_evidence_oid,
)
from libattest.formats.stmt_mappings import (
    ATTESTATION_STATEMENT_STRUCTURES,
    NONCE_REQUEST_STATEMENT_STRUCTURES,
    NONCE_RESPONSE_STATEMENT_STRUCTURES,
    get_nonce_request_statement_decoder,
    get_nonce_request_statement_structure,
    get_nonce_response_statement_structure,
)
from libattest.formats.tpm import (
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    encode_tpm20_quote_req_info,
    id_tpm20_quote_res,
)
from libattest.formats.tpm.pcr_selection import resolve_tpm_pcr_selection_oid
from libattest.formats.tpm.tcg import id_tcg_attest_quote
from libattest.x509 import CMW, ID_PE_CMW


def test_resolved_pcr_selection_oid_maps_to_tpm_quote_payload_types() -> None:
    """GIVEN the platform profile OID WHEN resolved THEN each nonce direction has its type."""
    oid = resolve_tpm_pcr_selection_oid()

    assert NONCE_REQUEST_STATEMENT_STRUCTURES[oid] is TPM20QuoteReqInfoASN1
    assert get_nonce_request_statement_structure(oid) is TPM20QuoteReqInfoASN1
    assert NONCE_RESPONSE_STATEMENT_STRUCTURES[oid] is TPM20QuoteRespInfoASN1
    assert NONCE_RESPONSE_STATEMENT_STRUCTURES[str(id_tpm20_quote_res)] is TPM20QuoteRespInfoASN1
    assert NONCE_RESPONSE_STATEMENT_STRUCTURES[str(id_tcg_attest_quote)] is TPM20QuoteRespInfoASN1
    assert get_nonce_response_statement_structure(oid) is TPM20QuoteRespInfoASN1


def test_back_compat_request_decoder_wraps_the_registered_structure() -> None:
    """GIVEN the deprecated decoder accessor WHEN called THEN it decodes via the structure map."""
    oid = resolve_tpm_pcr_selection_oid()
    der = encode_tpm20_quote_req_info(supported_hash_algos=[11])

    decoder = get_nonce_request_statement_decoder(oid)

    assert decoder is not None
    assert isinstance(decoder(der), TPM20QuoteReqInfoASN1)


def test_unknown_nonce_statement_oid_has_no_mapping() -> None:
    """GIVEN an unregistered OID WHEN resolved THEN no payload schema is guessed."""
    unknown_oid = "1.3.6.1.4.1.99999.999"

    assert get_nonce_request_statement_decoder(unknown_oid) is None
    assert get_nonce_request_statement_structure(unknown_oid) is None
    assert get_nonce_response_statement_structure(unknown_oid) is None


def test_key_attestation_and_encrypted_evidence_oids_map_to_their_asn1_structures() -> None:
    """GIVEN supported statement OIDs THEN their typed payloads are selected."""
    key_attest_oid = resolve_key_attest_evidence_oid()
    evidence_enc_oid = resolve_evidence_enc_oid()

    assert NONCE_RESPONSE_STATEMENT_STRUCTURES[key_attest_oid] is KeyAttestResp
    assert ATTESTATION_STATEMENT_STRUCTURES[key_attest_oid] is KeyAttestEvidence
    assert ATTESTATION_STATEMENT_STRUCTURES[evidence_enc_oid] is univ.OctetString
    assert ATTESTATION_STATEMENT_STRUCTURES[str(ID_PE_CMW)] is CMW


def test_key_attest_chall_and_evidence_enc_params_oids_map_to_their_asn1_structures() -> None:
    """GIVEN the KeyAttestChall reqInfo OID and the HPKE params respInfo OID THEN they resolve."""
    key_attest_oid = resolve_key_attest_evidence_oid()

    assert NONCE_REQUEST_STATEMENT_STRUCTURES[key_attest_oid] is KeyAttestChall
    assert get_nonce_request_statement_structure(key_attest_oid) is KeyAttestChall
    assert NONCE_RESPONSE_STATEMENT_STRUCTURES[EVIDENCE_ENC_PARAMS_OID] is rfc5280.SubjectPublicKeyInfo
    assert get_nonce_response_statement_structure(EVIDENCE_ENC_PARAMS_OID) is rfc5280.SubjectPublicKeyInfo
