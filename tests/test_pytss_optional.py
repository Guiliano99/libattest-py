# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""``tpm2-pytss`` is the optional ``[tpm]`` extra — prove the cheap build works.

Two properties are asserted, both in a subprocess with ``tpm2_pytss`` blocked at
the import system level (the in-process ``sys.modules`` is already polluted by
the real package, and ``conftest`` may have installed its stub):

* the RA-engine install surface imports with **no** ``tpm2-pytss`` present, so
  ``pip install libattest-py`` (without ``[tpm]``) is a usable build;
* the TPM modules, which genuinely require the native binding, fail with an
  ImportError that names the extra instead of a bare ``ModuleNotFoundError``.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src"

# Installs a meta-path finder that makes ``tpm2_pytss`` unimportable, emulating
# an install that skipped the ``[tpm]`` extra.  ``find_spec`` must *raise* (not
# return None) or the real finders further down ``sys.meta_path`` still win.
_BLOCK_PYTSS = """
import sys

class _Blocker:
    def find_spec(self, name, path=None, target=None):
        if name == "tpm2_pytss" or name.startswith("tpm2_pytss."):
            raise ImportError("No module named 'tpm2_pytss' (simulated absent extra)")
        return None

sys.meta_path.insert(0, _Blocker())
"""

# Import surface a cheap (RA-engine-only) install must keep working.
_PYTSS_FREE_MODULES = [
    "libattest",
    "libattest.ra",
    "libattest.formats.tpm",
    "libattest.formats.tpm.structures",
    "libattest.formats.tpm.asn1_types",
    "libattest.formats.tpm.attributes",
    "libattest.verifier",
    "verifier_service",
    "attest_client",
]

# Modules that legitimately need the native binding; they must say so clearly.
_PYTSS_REQUIRING_MODULES = [
    "libattest.formats.tpm.tpms_attest",
    "libattest.formats.tpm.tpm_signature",
    "libattest.formats.tpm.tpm_utils",
    "libattest.attester.tpm_client",
    "libattest.verifier.ek_store",
    "libattest.verifier.tpm",
]


def _run_without_pytss(body: str) -> subprocess.CompletedProcess[str]:
    """Run *body* in a subprocess where ``tpm2_pytss`` cannot be imported."""
    return subprocess.run(
        [sys.executable, "-c", _BLOCK_PYTSS + textwrap.dedent(body)],
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(_SRC), "PATH": "/usr/bin:/bin"},
        check=False,
        timeout=120,
    )


def test_blocker_actually_blocks() -> None:
    """GIVEN the blocker WHEN tpm2_pytss is imported THEN it fails.

    Guards the two tests below from silently passing because the blocker broke
    (it did once already: the legacy ``find_module`` hook is ignored on 3.12+).
    """
    result = _run_without_pytss(
        """
        try:
            import tpm2_pytss
        except ImportError:
            print("BLOCKED")
        """
    )
    assert "BLOCKED" in result.stdout, f"blocker is not working: {result.stdout}{result.stderr}"


@pytest.mark.parametrize("module", _PYTSS_FREE_MODULES)
def test_cheap_build_imports_without_pytss(module: str) -> None:
    """GIVEN no tpm2-pytss WHEN an RA-engine module is imported THEN it succeeds."""
    result = _run_without_pytss(
        f"""
        import {module}
        print("IMPORTED")
        """
    )
    assert result.returncode == 0, (
        f"{module} must import without the [tpm] extra so `pip install libattest-py` "
        f"stays a usable RA-engine build.\n{result.stderr}"
    )
    assert "IMPORTED" in result.stdout


@pytest.mark.parametrize("module", _PYTSS_REQUIRING_MODULES)
def test_tpm_modules_name_the_extra_when_pytss_is_absent(module: str) -> None:
    """GIVEN no tpm2-pytss WHEN a TPM module is imported THEN the error names the extra."""
    result = _run_without_pytss(
        f"""
        try:
            import {module}
        except ImportError as exc:
            print(str(exc))
        else:
            print("UNEXPECTED-SUCCESS")
        """
    )
    assert "UNEXPECTED-SUCCESS" not in result.stdout, f"{module} imported without pytss"
    assert "libattest-py[tpm]" in result.stdout, (
        f"{module} must fail with an actionable hint naming the [tpm] extra, "
        f"not a bare ModuleNotFoundError.\nGot: {result.stdout}{result.stderr}"
    )
