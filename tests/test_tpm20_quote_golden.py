# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Golden canonical-DER + range-constraint contract for TPM20Quote payloads.

The golden hex vectors below are the *exact* bytes the gencmpclient C encoder
(i2d_TPM20_QUOTE_REQ_INFO / i2d_TPM20_QUOTE_RESP_INFO, ``rats_csr_asn.c``) emits
for the same logical value. Because DER is canonical, the Python and C
encoders MUST agree byte-for-byte; this test is the cross-language anchor. If
it fails, the two ASN.1 definitions have drifted.
"""

from __future__ import annotations

import pytest

from libattest.formats.tpm.quote_profile import (
    decode_tpm20_quote_req_info,
    decode_tpm20_quote_resp_info,
    encode_tpm20_quote_req_info,
    encode_tpm20_quote_resp_info,
)

# TPM20QuoteReqInfo.certificateName/supportedHashAlgo are IMPLICIT [0]/[1]
# context-tagged (see quote_profile.TPM20QuoteReqInfoASN1) so the two OPTIONAL
# fields — which would otherwise share one universal SEQUENCE OF tag — decode
# unambiguously via schema-driven decode. rats_csr_asn.c's
# ASN1_IMP_SEQUENCE_OF_OPT(..., 0) / (..., 1) fields must match these tags.
REQ_GOLDEN = bytes.fromhex("300da0060c04616b2d31a10302010b")
# TPM20QuoteRespInfo's fields are unambiguous without tagging (certificateName
# is a plain UTF8String, not a SEQUENCE OF; pcrSelection/hashAlgo are
# mandatory), so this one carries its natural universal tags, unchanged.
RESP_GOLDEN = bytes.fromhex("301a0c04616b2d31300f02010002010102010202010302010402010b")

SHA256 = 11  # TPM_ALG_SHA256


def test_req_info_matches_c_golden_der() -> None:
    der = encode_tpm20_quote_req_info(certificate_names=["ak-1"], supported_hash_algos=[SHA256])
    assert der == REQ_GOLDEN
    assert decode_tpm20_quote_req_info(der) == (["ak-1"], [SHA256])


def test_resp_info_matches_c_golden_der() -> None:
    der = encode_tpm20_quote_resp_info(
        pcr_selection=[0, 1, 2, 3, 4], hash_algo=SHA256, certificate_name="ak-1"
    )
    assert der == RESP_GOLDEN
    assert decode_tpm20_quote_resp_info(der) == ("ak-1", [0, 1, 2, 3, 4], SHA256)


def test_pcr_index_out_of_range_rejected() -> None:
    with pytest.raises(ValueError):
        encode_tpm20_quote_resp_info(pcr_selection=[24], hash_algo=SHA256)


def test_tpm_alg_id_out_of_range_rejected() -> None:
    with pytest.raises(ValueError):
        encode_tpm20_quote_req_info(supported_hash_algos=[0x10000])
