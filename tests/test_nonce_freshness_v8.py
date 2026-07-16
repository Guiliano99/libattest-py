# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest
from pyasn1.codec.der import decoder, encoder
from pyasn1_alt_modules import rfc9480

from libattest import get_nonce_request_oid_for_name, get_nonce_response_oid_for_name
from libattest.formats import eareat_hpke
from libattest.formats.csrattest import (
    NonceRequest,
    NonceRequestTypeInfo,
    NonceResponse,
    NonceResponseTypeInfo,
    id_it_nonceRequest,
    id_it_nonceResponse,
)

NONCE = b"12345678901234567890123456789012"

_REQ_SAMPLE = Path("req1-genm.der")
_RESP_SAMPLE = Path("rsp1-genp.der")


def test_nonce_request_uses_req_type_info() -> None:
    req_der = eareat_hpke.build_nonce_request(length=32)

    request, rest = decoder.decode(req_der, asn1Spec=NonceRequest())

    assert rest == b""
    assert int(request["len"]) == 32
    assert isinstance(request["reqTypeInfo"], NonceRequestTypeInfo)
    assert str(request["reqTypeInfo"]["type"]) == get_nonce_request_oid_for_name("jose-hpke-evidence-params")


def test_nonce_response_uses_resp_type_info() -> None:
    response = NonceResponse()
    response["nonce"] = NONCE
    type_info = NonceResponseTypeInfo()
    type_info["type"] = get_nonce_response_oid_for_name("jose-hpke-evidence-params")
    type_info["respInfo"] = b"\x30\x00"
    response["respTypeInfo"] = type_info

    decoded, rest = decoder.decode(encoder.encode(response), asn1Spec=NonceResponse())

    assert rest == b""
    assert bytes(decoded["nonce"]) == NONCE
    assert isinstance(decoded["respTypeInfo"], NonceResponseTypeInfo)
    assert str(decoded["respTypeInfo"]["type"]) == get_nonce_response_oid_for_name("jose-hpke-evidence-params")
    assert bytes(decoded["respTypeInfo"]["respInfo"]) == b"\x30\x00"


def test_cmp_nonce_info_type_oids_are_draft_placeholders() -> None:
    # TBD1/TBD2 pending IANA assignment. These values are on the wire: they match
    # the infoType of req1-genm.der / rsp1-genp.der and the CMP MockCA.
    assert str(id_it_nonceRequest) == "1.2.840.113549.1.9.16.2.8888"
    assert str(id_it_nonceResponse) == "1.2.840.113549.1.9.16.2.8889"


@pytest.mark.skipif(not _REQ_SAMPLE.exists(), reason=f"{_REQ_SAMPLE} not present (local end-to-end capture)")
def test_genm_sample_infotype_and_quote_oid_match_the_constants() -> None:
    """GIVEN the checked-in genm capture WHEN decoded THEN its OIDs match the library constants.

    Pins the constants against real wire bytes rather than against themselves —
    ``test_cmp_nonce_info_type_oids_are_draft_placeholders`` above only catches
    someone editing the constant, never the constant silently drifting from
    what a real message actually carries.
    """
    pkimessage, rest = decoder.decode(_REQ_SAMPLE.read_bytes(), asn1Spec=rfc9480.PKIMessage())
    assert rest == b""

    itav = pkimessage["body"]["genm"][0]
    assert str(itav["infoType"]) == str(id_it_nonceRequest)

    nonce_request, rest = decoder.decode(bytes(itav["infoValue"]), asn1Spec=NonceRequest())
    assert rest == b""
    assert str(nonce_request["reqTypeInfo"]["type"]) == get_nonce_request_oid_for_name("tpm-quote")


@pytest.mark.skipif(not _RESP_SAMPLE.exists(), reason=f"{_RESP_SAMPLE} not present (local end-to-end capture)")
def test_genp_sample_infotype_and_quote_oid_match_the_constants() -> None:
    """GIVEN the checked-in genp capture WHEN decoded THEN its OIDs match the library constants."""
    pkimessage, rest = decoder.decode(_RESP_SAMPLE.read_bytes(), asn1Spec=rfc9480.PKIMessage())
    assert rest == b""

    itav = pkimessage["body"]["genp"][0]
    assert str(itav["infoType"]) == str(id_it_nonceResponse)

    nonce_response, rest = decoder.decode(bytes(itav["infoValue"]), asn1Spec=NonceResponse())
    assert rest == b""
    assert str(nonce_response["respTypeInfo"]["type"]) == get_nonce_response_oid_for_name("tpm-quote")
