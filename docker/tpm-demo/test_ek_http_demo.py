# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Real-TPM test for the HTTP EK credential-activation demo.

Requires a reachable TPM (same gating as ``test_demo.py``).  Preferred:
``docker compose run --rm client python -m pytest docker/tpm-demo/test_ek_http_demo.py``.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ek_http_demo  # noqa: E402

from libattest.attester.tpm_client import TpmClient  # noqa: E402

TCTI = os.environ.get("TCTI", "libtpms:")


def _require_tpm() -> None:
    """Skip when no TPM is reachable at ``TCTI``."""
    try:
        TpmClient(tcti=TCTI).connect().close()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"no reachable TPM at {TCTI}: {exc}")


def test_ek_http_demo_accepts_recovered_seed(capsys):
    """Device submits EK over HTTP, then recovers the verifier's wrapped seed."""
    _require_tpm()
    assert ek_http_demo.run_demo(tcti=TCTI)
    assert "Verdict:           ACCEPT" in capsys.readouterr().out


def test_bind_check_rejects_mismatched_public():
    """The verifier rejects an EK cert whose key does not match the TPM2B_PUBLIC."""
    _require_tpm()
    import tempfile

    from provision_ek import mint_demo_ek_cert, provision

    from libattest.verifier.ek_store import EkStore

    with tempfile.TemporaryDirectory() as out_dir:
        tpm, _ak_name, (raw_path, _pem_path) = provision(out_dir, TCTI)
        try:
            with open(raw_path, "rb") as fh:
                ek_raw = fh.read()
            # A cert over a DIFFERENT key (the AK, not the EK) must fail the bind check.
            wrong_cert = mint_demo_ek_cert(tpm.ak_public)
        finally:
            tpm.close()

    with pytest.raises(ValueError, match="does not match"):
        EkStore().submit(wrong_cert, ek_raw)
