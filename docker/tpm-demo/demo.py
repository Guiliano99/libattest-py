# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Run the readable libattest TPM demos against the live mssim simulator.

This script is intentionally small: it gives the Docker demo folder a stable
``python docker/tpm-demo/demo.py`` command that runs both self-contained demo
modules (``platform_attest_demo`` and ``key_attest_demo``) in this folder.
"""

from __future__ import annotations

import os
import sys

# Allow `python docker/tpm-demo/demo.py` (run from the repo root) to import the
# sibling demo modules in this folder.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ek_http_demo import run_demo as run_ek_http_demo  # noqa: E402
from key_attest_demo import run_demo as run_key_demo  # noqa: E402
from platform_attest_demo import run_demo as run_platform_demo  # noqa: E402


def main() -> None:
    """Run the platform demo, the key-attestation demo, then the HTTP EK demo."""
    platform_ok = run_platform_demo()
    print()
    key_ok = run_key_demo()
    print()
    ek_http_ok = run_ek_http_demo()
    raise SystemExit(0 if platform_ok and key_ok and ek_http_ok else 1)


if __name__ == "__main__":
    main()
