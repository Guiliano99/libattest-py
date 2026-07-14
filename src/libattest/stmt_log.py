# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Opt-in display of generated attestation statements.

The attester-side generators build a statement and hand the caller opaque DER;
by default nothing is shown. When a demo exports ``LIBATTEST_LOG_STMT=1`` (e.g.
from ``request-certificate.bash``), :func:`log_statement` renders each generated
statement to stderr so the operator driving the enrolment sees it — the attester
runs inside gencmpclient's embedded CPython, whose stderr is shared with the
terminal running the enrolment.

libattest configures no logging handlers of its own (the host owns wiring), so
this module attaches its own stderr handler *only* when the flag is set, and is
otherwise a silent no-op.
"""

from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)

_ENV = "LIBATTEST_LOG_STMT"
_HANDLER_NAME = "libattest-stmt-log"
_TRUTHY = ("1", "true", "yes")


def maybe_enable_stmt_logging() -> None:
    """Attach a stderr handler and DEBUG level to the ``libattest`` logger when opted in.

    Reads ``LIBATTEST_LOG_STMT``; when truthy, ensures a single tagged stderr
    handler is attached to the top-level ``libattest`` logger and its level is at
    least DEBUG. Idempotent — safe to call from every generator on every call.
    A no-op when the flag is unset.
    """
    if (os.environ.get(_ENV) or "").strip().lower() not in _TRUTHY:
        return
    root = logging.getLogger("libattest")
    if not any(getattr(h, "name", None) == _HANDLER_NAME for h in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.name = _HANDLER_NAME
        handler.setFormatter(logging.Formatter("[libattest] %(message)s"))
        root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > logging.DEBUG:
        root.setLevel(logging.DEBUG)


def log_statement(label: str, statement: object, type_oid: str | None = None) -> None:
    """Render a just-generated statement at DEBUG, honouring ``LIBATTEST_LOG_STMT``.

    Enables opt-in logging first, then (only when DEBUG is active) renders a
    pyasn1 ``statement`` via ``prettyPrint()`` or, for ``bytes`` (DER/CBOR), its
    length and hex. Best-effort display: any rendering error is swallowed so the
    enrolment is never broken by logging.
    """
    maybe_enable_stmt_logging()
    if not logger.isEnabledFor(logging.DEBUG):
        return
    suffix = f" (type={type_oid})" if type_oid else ""
    try:
        pretty = getattr(statement, "prettyPrint", None)
        if callable(pretty):
            logger.debug("generated %s%s:\n%s", label, suffix, pretty())
        else:
            raw = bytes(statement)  # type: ignore[arg-type]
            logger.debug("generated %s%s: %d bytes (hex):\n%s", label, suffix, len(raw), raw.hex())
    except Exception:
        logger.debug("generated %s%s: <unrenderable>", label, suffix)
