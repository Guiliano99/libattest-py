# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Guard for the optional ``tpm2-pytss`` dependency.

Producing and appraising TPM evidence needs the native ``tpm2-pytss`` binding,
which in turn pulls in the TSS2 C libraries.  That is a heavy dependency, and
callers who only need the RA engine (:mod:`libattest.ra`) or the pyasn1-only
TPM codecs (:mod:`libattest.formats.tpm.quote_profile`, ``.tcg``) never touch
it — so it is packaged as the ``[tpm]`` extra rather than a hard requirement.

Modules that genuinely need ``tpm2-pytss`` call :func:`require_pytss` directly
above their ``from tpm2_pytss import ...`` line.  Without the guard those
modules fail with a bare ``ModuleNotFoundError: No module named 'tpm2_pytss'``,
which does not tell the reader that an extra exists; with it they fail naming
the install command.
"""

from __future__ import annotations

_INSTALL_HINT = (
    "TPM attestation features require the optional 'tpm2-pytss' dependency, "
    "which is not importable.\n"
    "Install it with:  pip install 'libattest-py[tpm]'\n"
    "tpm2-pytss also needs the TSS2 system libraries "
    "(e.g. 'apt install libtss2-dev libtss2-tcti-libtpms0')."
)


def require_pytss() -> None:
    """Raise a clear :exc:`ImportError` when ``tpm2_pytss`` is unavailable.

    Raises
    ------
    ImportError
        If ``tpm2_pytss`` cannot be imported, either because the ``[tpm]`` extra
        is not installed or because its compiled extension cannot load its TSS2
        shared objects.  The original failure is chained as ``__cause__``.

    """
    try:
        import tpm2_pytss  # noqa: F401, PLC0415
    except Exception as exc:  # noqa: BLE001 - ImportError *or* a native load failure (OSError)
        raise ImportError(f"{_INSTALL_HINT}\n\nUnderlying import error: {exc!r}") from exc
