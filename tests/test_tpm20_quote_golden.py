# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Golden canonical-DER + range-constraint contract for TPM20Quote payloads.

The golden hex vectors below are the *exact* bytes emitted by the gencmpclient C
encoder (i2d_TPM20_QUOTE_REQ_INFO / i2d_TPM20_QUOTE_RESP_INFO) — captured from the
g2 build smoke.  Because DER is canonical, the Python and C encoders MUST agree
byte-for-byte for the same logical value; this test is the cross-language anchor.
If it fails, the two ASN.1 definitions have drifted.
"""

from __future__ import annotations

import pytest

from libattest.formats.tpm.quote_profile import (
    decode_tpm20_quote_req_info,
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_req_info,
    encode_tpm20_quote_resp_info,
)

# TPM20QuoteReqInfo.certificateName/supportedHashAlgo carry their natural
# universal SEQUENCE-OF tags, matching the gencmpclient C encoder's
# historical untagged form (i2d_TPM20_QUOTE_REQ_INFO) — byte-for-byte
# cross-language interop. The two OPTIONAL fields share the SEQUENCE tag but
# have distinct inner element types (UTF8String vs INTEGER); a message
# carrying both (the shape every demo sends) decodes unambiguously. See
# docs/adr/0003-asn1-utils-and-strict-der-decoding.md (revert note).
REQ_GOLDEN = bytes.fromhex("301730100c02616b0c04616b2d320c04616b2d33300302010b")
# Emitted by the gencmpclient C smoke (scratchpad/g2build), untagged SEQUENCE OF.
RESP_GOLDEN = bytes.fromhex("30180c02616b300f02010002010102010202010302010402010b")

SHA256 = 11  # TPM_ALG_SHA256


def test_default_req_info_matches_c_golden_der() -> None:
    der = encode_tpm20_quote_req_info(supported_hash_algos=[SHA256])
    assert der == REQ_GOLDEN
    assert decode_tpm20_quote_req_info(der) == (["ak", "ak-2", "ak-3"], [SHA256])


def test_resp_info_matches_c_golden_der() -> None:
    der = encode_tpm20_quote_resp_info(
        pcr_selection=[0, 1, 2, 3, 4], hash_algo=SHA256, certificate_name="ak"
    )
    assert der == RESP_GOLDEN
    assert decode_tpm20_quote_resp_info(der) == ("ak", [0, 1, 2, 3, 4], SHA256)


def test_pcr_index_out_of_range_rejected() -> None:
    with pytest.raises(ValueError):
        encode_tpm20_quote_resp_info(pcr_selection=[24], hash_algo=SHA256)


def test_tpm_alg_id_out_of_range_rejected() -> None:
    with pytest.raises(ValueError):
        encode_tpm20_quote_req_info(supported_hash_algos=[0x10000])
