import json

import pytest
from pyasn1.codec.der import decoder

from libattest.formats.tpm.pcr_selection import (
    TpmPcrSelectionInfoASN1,
    decode_tpm_pcr_selection_info,
    encode_tpm_pcr_selection_info,
    encode_tpm_pcr_selection_info_from_parts,
    pcr_selection_response_info,
    resolve_tpm_pcr_selection_oid,
    tpm_pcr_selection_json_value,
)


def test_tpm_pcr_selection_respinfo_is_oid_and_utf8_json():
    der = encode_tpm_pcr_selection_info_from_parts(pcrs=[0, 1, 2, 3, 4], hash_alg_id=0x000B)

    decoded, rest = decoder.decode(der, asn1Spec=TpmPcrSelectionInfoASN1())

    assert rest == b""
    assert str(decoded["type"]) == resolve_tpm_pcr_selection_oid()
    payload = json.loads(str(decoded["value"]))
    assert payload == {
        "pcrSelection": [
            {
                "hash": "sha256",
                "pcrs": [0, 1, 2, 3, 4],
            }
        ]
    }


def test_tpm_pcr_selection_reqinfo_can_carry_hash_only_json():
    der = encode_tpm_pcr_selection_info_from_parts(hash_alg_id=0x000B)

    assert tpm_pcr_selection_json_value(der) == {
        "pcrSelection": [
            {
                "hash": "sha256",
            }
        ]
    }
    assert decode_tpm_pcr_selection_info(der) == (None, 0x000B)


def test_response_param_helper_uses_oid_value_utf8_json_wire_format():
    any_value = pcr_selection_response_info(pcrs=[4, 3, 2, 1, 0], hash_alg_id=0x000B)

    assert decode_tpm_pcr_selection_info(bytes(any_value)) == ([0, 1, 2, 3, 4], 0x000B)


def test_decode_rejects_empty_pcr_selection_entry():
    der = encode_tpm_pcr_selection_info_from_parts(hash_alg_id=0x000B)
    payload = tpm_pcr_selection_json_value(der)
    payload["pcrSelection"] = [{}]
    malformed = encode_tpm_pcr_selection_info(payload)

    with pytest.raises(ValueError, match="at least one"):
        decode_tpm_pcr_selection_info(malformed)


def test_decode_rejects_non_string_hash_value():
    der = encode_tpm_pcr_selection_info_from_parts(hash_alg_id=0x000B)
    payload = tpm_pcr_selection_json_value(der)
    payload["pcrSelection"] = [{"hash": 123}]
    malformed = encode_tpm_pcr_selection_info(payload)

    with pytest.raises(ValueError, match="hash"):
        decode_tpm_pcr_selection_info(malformed)
