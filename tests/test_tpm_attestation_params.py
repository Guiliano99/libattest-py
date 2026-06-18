# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the typed ASN.1 TpmAttestationParams reqInfo/respInfo profile."""

from __future__ import annotations

import pytest
from pyasn1.type import univ

from libattest.formats.tpm import (
    attestation_params_from_response_info,
    attestation_params_request_info,
    attestation_params_response_info,
    decode_tpm_attestation_params,
    encode_tpm_attestation_params,
    pcr_indices_to_mask,
    pcr_mask_to_indices,
)

TPM_ALG_SHA256 = 0x000B


def test_round_trip_pcrs_and_hash():
    der = encode_tpm_attestation_params([0, 1, 2, 3, 4], TPM_ALG_SHA256)
    pcrs, hash_alg_id = decode_tpm_attestation_params(der)
    assert pcrs == [0, 1, 2, 3, 4]
    assert hash_alg_id == TPM_ALG_SHA256


def test_hash_only_matches_c_side_wire_bytes():
    # The OpenSSL fork's build_tpm_hash_proposal_der(0x000B) emits exactly
    # SEQUENCE { INTEGER 11 } = 30 03 02 01 0B.  The Python encoder must be
    # byte-identical for cross-implementation interop.
    der = encode_tpm_attestation_params(hash_alg_id=TPM_ALG_SHA256)
    assert der == bytes.fromhex("300302010b")
    pcrs, hash_alg_id = decode_tpm_attestation_params(der)
    assert pcrs is None
    assert hash_alg_id == TPM_ALG_SHA256


def test_pcrs_only_round_trip():
    der = encode_tpm_attestation_params([7, 0, 7, 3])
    pcrs, hash_alg_id = decode_tpm_attestation_params(der)
    assert pcrs == [0, 3, 7]  # deduplicated and sorted
    assert hash_alg_id is None


def test_encode_rejects_missing_fields_and_bad_values():
    with pytest.raises(ValueError):
        encode_tpm_attestation_params()
    with pytest.raises(ValueError):
        encode_tpm_attestation_params([])
    with pytest.raises(ValueError):
        encode_tpm_attestation_params([24], TPM_ALG_SHA256)
    with pytest.raises(ValueError):
        encode_tpm_attestation_params([-1], TPM_ALG_SHA256)
    with pytest.raises(ValueError):
        encode_tpm_attestation_params([0], 0)
    with pytest.raises(ValueError):
        encode_tpm_attestation_params([0], 0x1_0000)


def test_decode_rejects_garbage_and_trailing_bytes():
    with pytest.raises(ValueError):
        decode_tpm_attestation_params(b"\x02\x01\x0b")
    with pytest.raises(ValueError):
        decode_tpm_attestation_params(bytes.fromhex("300302010b") + b"\x00")
    with pytest.raises(ValueError):
        decode_tpm_attestation_params(bytes.fromhex("3000"))  # both fields absent


def test_request_and_response_info_helpers_round_trip():
    req_info = attestation_params_request_info(hash_alg_id=TPM_ALG_SHA256)
    assert isinstance(req_info, univ.Any)
    assert attestation_params_from_response_info(req_info) == (None, TPM_ALG_SHA256)

    resp_info = attestation_params_response_info([0, 1, 2, 3, 4], TPM_ALG_SHA256)
    assert attestation_params_from_response_info(resp_info) == (
        [0, 1, 2, 3, 4],
        TPM_ALG_SHA256,
    )
    assert attestation_params_from_response_info(None) is None


def test_pcr_mask_helpers_round_trip():
    mask = pcr_indices_to_mask([0, 1, 2, 3, 4])
    assert mask == b"\x1f\x00\x00"
    assert pcr_mask_to_indices(mask) == [0, 1, 2, 3, 4]
    assert pcr_mask_to_indices(pcr_indices_to_mask([23])) == [23]
    assert pcr_mask_to_indices(b"\x00\x00\x00") == []
    with pytest.raises(ValueError):
        pcr_indices_to_mask([-1])
