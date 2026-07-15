# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pytest
from pyasn1.type import univ

from libattest.formats.tpm import (
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    decode_tpm20_quote_req_info,
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_req_info,
    encode_tpm20_quote_resp_info,
    id_tpm20_quote_req,
    id_tpm20_quote_res,
    tpm20_quote_request_info,
    tpm20_quote_response_info,
)

TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B


def test_quote_request_info_round_trips_certificate_names_and_hash_algorithms() -> None:
    der = encode_tpm20_quote_req_info(
        certificate_names=["ak-a", "ak-b"],
        supported_hash_algos=[TPM_ALG_SHA1, TPM_ALG_SHA256],
    )

    certificate_names, supported_hash_algos = decode_tpm20_quote_req_info(der)

    assert certificate_names == ["ak-a", "ak-b"]
    assert supported_hash_algos == [TPM_ALG_SHA1, TPM_ALG_SHA256]


def test_quote_response_info_round_trips_single_pcr_bank_selection() -> None:
    der = encode_tpm20_quote_resp_info(
        certificate_name="ak-a",
        pcr_selection=[4, 0, 4, 2],
        hash_algo=TPM_ALG_SHA256,
    )

    certificate_name, pcr_selection, hash_algo = decode_tpm20_quote_resp_info(der)

    assert certificate_name == "ak-a"
    assert pcr_selection == [0, 2, 4]
    assert hash_algo == TPM_ALG_SHA256


def test_quote_info_helpers_return_any_payloads() -> None:
    req_info = tpm20_quote_request_info(supported_hash_algos=[TPM_ALG_SHA256])
    resp_info = tpm20_quote_response_info(pcr_selection=[0, 1, 2, 3], hash_algo=TPM_ALG_SHA256)

    assert isinstance(req_info, univ.Any)
    assert isinstance(resp_info, univ.Any)
    assert decode_tpm20_quote_req_info(req_info) == (None, [TPM_ALG_SHA256])
    assert decode_tpm20_quote_resp_info(resp_info) == (None, [0, 1, 2, 3], TPM_ALG_SHA256)


def test_quote_profile_exports_distinct_request_and_response_type_oids() -> None:
    # Request and response are distinct wire positions and carry distinct OIDs.
    # These exact values are on the checked-in end-to-end example messages
    # (req1-genm.der / rsp1-genp.der) and are matched by the gencmpclient C
    # attester, so changing them invalidates both. Env-overridable in lockstep
    # via TPM_PCR_SELECTION_OID / TPM_QUOTE_RESP_OID.
    assert str(id_tpm20_quote_req) == "1.2.3.4.5"
    assert str(id_tpm20_quote_res) == "1.2.3.4.6"
    assert str(id_tpm20_quote_req) != str(id_tpm20_quote_res)


def test_quote_response_rejects_empty_pcr_selection_and_bad_hash() -> None:
    with pytest.raises(ValueError):
        encode_tpm20_quote_resp_info(pcr_selection=[], hash_algo=TPM_ALG_SHA256)
    with pytest.raises(ValueError):
        encode_tpm20_quote_resp_info(pcr_selection=[0], hash_algo=0x1_0000)


def test_quote_profile_asn1_names_are_exported() -> None:
    assert TPM20QuoteReqInfoASN1.__name__ == "TPM20QuoteReqInfoASN1"
    assert TPM20QuoteRespInfoASN1.__name__ == "TPM20QuoteRespInfoASN1"
