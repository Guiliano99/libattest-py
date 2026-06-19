# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Test configuration and environment shims.

Some hosts ship ``tpm2-pytss`` whose compiled extension links against
``libtss2-policy.so.0`` even though that shared object is not installed
(the ``libtss2-policy0`` package is missing).  In that situation *any*
import of ``tpm2_pytss`` — and therefore of ``libattest.formats.tpm``
(its package ``__init__`` eagerly imports ``tpms_attest``) — fails at
collection time, which would block every pure-Python TPM-format test
(``TpmAttestationParams`` codecs, PCR-selection JSON, the respInfo
registry, and the new ``libattest.ra`` engine tests) even though none of
them touch the native library.

To keep those pure-Python tests runnable, this conftest installs a minimal
``tpm2_pytss`` stub into :data:`sys.modules` **only when the real package
cannot be imported**.  The stub exposes the ``TPM2_ALG`` algorithm
constants used by ``tpms_attest`` at import time.  Its ``TPMS_ATTEST``
placeholder raises on ``unmarshal``, so the genuinely hardware/native
tests that parse a real ``TPMS_ATTEST`` buffer are skipped (collected but
not silently passed) — those are the ``±`` TPM-native tests that require
the real library.
"""

from __future__ import annotations

import sys

import pytest

# Test modules that need a real ``tpm2_pytss`` (they unmarshal genuine
# ``TPMS_ATTEST`` buffers); skipped when only the stub is available.
_NATIVE_TPM_TEST_FILES = (
    "test_platform_appraisal.py",
    "test_tpm_verifier_classes.py",
)

_TPM_STUB_ACTIVE = False


def _install_tpm2_pytss_stub() -> bool:
    """Install a minimal ``tpm2_pytss`` stub if the real one is unimportable.

    Returns ``True`` when a stub was installed (real import failed), ``False``
    when the real package imported cleanly.
    """
    try:
        import tpm2_pytss  # noqa: F401

        return False
    except Exception:  # noqa: BLE001 — ImportError or native-load failure
        pass

    import types

    # TPM_ALG_ID values (TCG TPM 2.0 Library Part 2, Table 9) used by
    # ``libattest.formats.tpm.tpms_attest`` at import time.
    class _TPM2_ALG:
        SHA1 = 0x0004
        SHA256 = 0x000B
        SHA384 = 0x000C
        SHA512 = 0x000D
        RSASSA = 0x0014
        RSAPSS = 0x0016
        ECDSA = 0x0018

    class _TPMS_ATTEST:
        """Placeholder that refuses to unmarshal real buffers."""

        @staticmethod
        def unmarshal(_data):  # pragma: no cover - native path not exercised
            raise RuntimeError(
                "tpm2_pytss is stubbed (libtss2-policy.so.0 missing); "
                "real TPMS_ATTEST parsing is unavailable in this environment"
            )

    stub = types.ModuleType("tpm2_pytss")
    stub.TPM2_ALG = _TPM2_ALG
    stub.TPMS_ATTEST = _TPMS_ATTEST
    stub.__libattest_stub__ = True
    sys.modules["tpm2_pytss"] = stub
    return True


_TPM_STUB_ACTIVE = _install_tpm2_pytss_stub()


def pytest_collection_modifyitems(config, items):  # noqa: D401
    """Skip native-TPM tests when only the ``tpm2_pytss`` stub is available."""
    if not _TPM_STUB_ACTIVE:
        return
    skip_native = pytest.mark.skip(
        reason="tpm2_pytss unavailable (libtss2-policy.so.0 missing); "
        "native TPMS_ATTEST parsing required"
    )
    for item in items:
        if item.fspath.basename in _NATIVE_TPM_TEST_FILES:
            item.add_marker(skip_native)
