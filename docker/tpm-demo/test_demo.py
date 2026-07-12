# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Real-TPM tests for the relocated libattest TPM demos.

Require a reachable TPM.  Two ways to satisfy that:

* **Docker** (preferred): ``make tpm-test`` builds the images and runs this
  module inside the ``client`` container against the ``tpmsim`` service
  (``TCTI=mssim:host=tpmsim,port=2321``).
* **Local**: install ``libtss2-dev`` + ``tpm2-pytss``; the default ``libtpms:``
  TCTI runs the IBM software TPM in-process — no Docker needed
  (``make tpm-test-local``).

``tpm2-pytss`` is a mandatory dependency, so it is always importable; only a
reachable TPM is gated, via :func:`_require_tpm`.
"""

from __future__ import annotations

import os
import sys

import pytest

# This folder is not an importable package; put it on the path so the sibling
# demo modules import whether run via `pytest docker/tpm-demo/test_demo.py` or
# directly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import key_attest_demo  # noqa: E402
import platform_attest_demo  # noqa: E402

from libattest.attester.tpm_client import TpmClient  # noqa: E402

TCTI = os.environ.get("TCTI", "libtpms:")


def _require_tpm() -> None:
    """Skip the test when no TPM is reachable at ``TCTI``."""
    try:
        TpmClient(tcti=TCTI).connect().close()
    except Exception as exc:  # noqa: BLE001 - TSS2_Exception or TCTI load failure
        pytest.skip(f"no reachable TPM at {TCTI}: {exc}")


def test_platform_demo_accepts_real_quote(capsys):
    """The platform demo runs a real TPM2_Quote that the verifier accepts."""
    _require_tpm()
    assert platform_attest_demo.run_demo(tcti=TCTI)
    assert "Verdict:       ACCEPT" in capsys.readouterr().out


def test_key_demo_recovers_activation_seed(capsys):
    """The key demo recovers the verifier's seed via TPM2_ActivateCredential."""
    _require_tpm()
    assert key_attest_demo.run_demo(tcti=TCTI)
    out = capsys.readouterr().out
    assert "recovered == seed: True" in out
    assert "ACCEPT" in out
