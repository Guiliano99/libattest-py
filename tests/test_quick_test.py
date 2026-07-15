# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the root-level JWT/CWT preview harness."""

# pylint: disable=wrong-import-order
from __future__ import annotations

import cbor2
import quick_test
from cwt import COSE, COSEHeaders

from libattest.formats.eat_ear.cwt_jwt_utils import generate_es256_keypair


def test_quick_test_labels_unsigned_and_unverified_conversion_output(tmp_path, capsys) -> None:
    """GIVEN both preview flags WHEN the harness runs THEN each trust boundary is printed."""
    signing_key, _verify_key, _private_pem, _public_pem = generate_es256_keypair("quick-test")
    cwt_path = tmp_path / "signed.cwt"
    cwt_path.write_bytes(
        COSE.new().encode_and_sign(
            cbor2.dumps({"sub": "device"}),
            signing_key,
            protected={COSEHeaders.ALG: signing_key.alg},
        )
    )

    assert quick_test.main(quick_test.parse_args(["--jwt-to-cwt", "--cwt-to-jwt", str(cwt_path)])) == 0

    output = capsys.readouterr().out
    assert "UNSIGNED CWT Claim Set converted from the verified token:" in output
    assert "UNVERIFIED JWT-style CWT view from" in output
