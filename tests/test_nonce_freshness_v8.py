# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pyasn1.codec.der import decoder, encoder

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
    assert str(id_it_nonceRequest) == "1.3.6.1.5.5.7.4.98"
    assert str(id_it_nonceResponse) == "1.3.6.1.5.5.7.4.99"
