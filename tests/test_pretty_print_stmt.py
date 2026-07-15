# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the attester-side CMP nonce auto-decode/pretty-print behavior."""

from __future__ import annotations

from pathlib import Path

import pytest
from pyasn1.type import univ

from libattest import get_nonce_request_oid_for_name, get_nonce_response_oid_for_name
from libattest.formats.csrattest import (
    NonceRequest,
    NonceRequestTypeInfo,
    NonceResponse,
    NonceResponseTypeInfo,
)
from libattest.formats.csrattest.pretty_print_cmp_stmt import (
    _decode_req_info,
    _decode_resp_info,
    parse_genm_pkimessage,
    parse_genp_pkimessage,
)
from libattest.formats.tpm import (
    TPM20QuoteReqInfoASN1,
    TPM20QuoteRespInfoASN1,
    tpm20_quote_request_info,
    tpm20_quote_response_info,
)


def _quote_request() -> NonceRequest:
    """Build the TPM PCR-selection nonce request seen on the attester wire."""
    request = NonceRequest()
    request["len"] = 32
    request["reqTypeInfo"] = NonceRequestTypeInfo()
    request["reqTypeInfo"]["type"] = univ.ObjectIdentifier(get_nonce_request_oid_for_name("tpm-quote"))
    request["reqTypeInfo"]["reqInfo"] = tpm20_quote_request_info(
        certificate_names=["ak"],
        supported_hash_algos=[0x000B],
    )
    return request


def _quote_response() -> NonceResponse:
    """Build the TPM PCR-selection nonce response seen on the attester wire."""
    response = NonceResponse()
    response["nonce"] = b"n" * 32
    response["respTypeInfo"] = NonceResponseTypeInfo()
    response["respTypeInfo"]["type"] = univ.ObjectIdentifier(get_nonce_response_oid_for_name("tpm-quote"))
    response["respTypeInfo"]["respInfo"] = tpm20_quote_response_info(
        pcr_selection=[0, 1, 2, 3, 4],
        hash_algo=0x000B,
    )
    return response


def test_decode_req_info_decodes_tpm_quote_request() -> None:
    """GIVEN a TPM PCR-selection request WHEN decoded THEN its typed payload is produced."""
    decoded = _decode_req_info(_quote_request())

    assert isinstance(decoded, TPM20QuoteReqInfoASN1)
    output = decoded.prettyPrint()
    assert "ak" in output
    assert "11" in output


def test_decode_resp_info_decodes_tpm_quote_response() -> None:
    """GIVEN a TPM PCR-selection response WHEN decoded THEN its typed payload is produced."""
    decoded = _decode_resp_info(_quote_response())

    assert isinstance(decoded, TPM20QuoteRespInfoASN1)
    output = decoded.prettyPrint()
    assert "pcrSelection=_PCRIndexSequence:" in output
    assert "hashAlgo=11" in output


def test_parse_genm_pkimessage_overwrites_req_info_with_decoded_structure() -> None:
    """GIVEN the sample genm DER WHEN parsed THEN reqInfo is replaced by its decoded structure."""
    pkimessage = parse_genm_pkimessage(Path("req1-genm.der").read_bytes())
    nonce_request = pkimessage["body"]["genm"][0]["infoValue"]

    assert isinstance(nonce_request["reqTypeInfo"]["reqInfo"], TPM20QuoteReqInfoASN1)
    assert "TPM20QuoteReqInfoASN1:" in nonce_request.prettyPrint()


def test_parse_genp_pkimessage_overwrites_resp_info_with_decoded_structure() -> None:
    """GIVEN the sample genp DER WHEN parsed THEN respInfo is replaced by its decoded structure."""
    pkimessage = parse_genp_pkimessage(Path("rsp1-genp.der").read_bytes())
    nonce_response = pkimessage["body"]["genp"][0]["infoValue"]

    assert isinstance(nonce_response["respTypeInfo"]["respInfo"], TPM20QuoteRespInfoASN1)
    assert "TPM20QuoteRespInfoASN1:" in nonce_response.prettyPrint()


def test_decode_req_info_raises_on_unregistered_oid() -> None:
    """GIVEN a reqTypeInfo with an unregistered OID WHEN decoded THEN ValueError is raised."""
    request = NonceRequest()
    request["reqTypeInfo"] = NonceRequestTypeInfo()
    request["reqTypeInfo"]["type"] = univ.ObjectIdentifier("1.3.6.1.4.1.99999.999")
    request["reqTypeInfo"]["reqInfo"] = univ.Any(b"\x04\x01\x00")

    with pytest.raises(ValueError, match="NONCE_REQUEST_STATEMENT_STRUCTURES"):
        _decode_req_info(request)


def test_decode_resp_info_raises_on_unregistered_oid() -> None:
    """GIVEN a respTypeInfo with an unregistered OID WHEN decoded THEN ValueError is raised."""
    response = NonceResponse()
    response["nonce"] = b"n" * 32
    response["respTypeInfo"] = NonceResponseTypeInfo()
    response["respTypeInfo"]["type"] = univ.ObjectIdentifier("1.3.6.1.4.1.99999.999")
    response["respTypeInfo"]["respInfo"] = univ.Any(b"\x04\x01\x00")

    with pytest.raises(ValueError, match="NONCE_RESPONSE_STATEMENT_STRUCTURES"):
        _decode_resp_info(response)
