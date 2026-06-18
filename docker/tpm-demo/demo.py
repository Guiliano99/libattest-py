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

from key_attest_demo import run_demo as run_key_demo  # noqa: E402
from platform_attest_demo import run_demo as run_platform_demo  # noqa: E402


def main() -> None:
    """Run the platform demo, then the key-attestation demo."""
    platform_ok = run_platform_demo()
    print()
    key_ok = run_key_demo()
    raise SystemExit(0 if platform_ok and key_ok else 1)


if __name__ == "__main__":
    main()
