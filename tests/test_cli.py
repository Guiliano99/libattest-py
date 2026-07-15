# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the auto-dispatching genm/genp CLI entry point."""

from __future__ import annotations

# pylint: disable=wrong-import-order
from cli import main, parse_args

# pylint: enable=wrong-import-order


def test_cli_auto_dispatches_genm_and_genp_sample_files(capsys) -> None:
    """GIVEN the repo's sample genm and genp DER files WHEN run THEN both print without error."""
    args = parse_args(["req1-genm.der", "rsp1-genp.der"])

    exit_code = main(args)

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "NonceRequest:" in output
    assert "NonceResponse:" in output
