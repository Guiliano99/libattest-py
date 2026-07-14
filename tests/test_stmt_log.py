# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the opt-in generated-statement logger (``LIBATTEST_LOG_STMT``).

These pin the observable contract the demos rely on: nothing is emitted unless
the flag is set, and when it is, a pyasn1 statement renders via ``prettyPrint``
while raw DER/CBOR renders as length + hex — on stderr, so the embedded-CPython
attester's output reaches the terminal driving the enrolment.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

from libattest import stmt_log


class _FakeStmt:
    """Stand-in pyasn1 statement whose ``prettyPrint`` output we can assert on."""

    def prettyPrint(self) -> str:  # noqa: N802 - mirror pyasn1's method name
        """Return a recognisable rendering."""
        return "TcgAttestCertify:\n  magic=0xff544347"


@pytest.fixture(autouse=True)
def _reset_libattest_logger():
    """GIVEN a clean ``libattest`` logger WHEN a test runs THEN its handler/level are restored."""
    root = logging.getLogger("libattest")
    saved_handlers, saved_level = root.handlers[:], root.level
    yield
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)


def _capture(monkeypatch: pytest.MonkeyPatch, flag: str | None, statement: object, oid: str | None = None) -> str:
    """Run ``log_statement`` with the flag set (or not) and return captured stderr."""
    if flag is None:
        monkeypatch.delenv("LIBATTEST_LOG_STMT", raising=False)
    else:
        monkeypatch.setenv("LIBATTEST_LOG_STMT", flag)
    buf = io.StringIO()
    monkeypatch.setattr(sys, "stderr", buf)
    stmt_log.log_statement("Evidence", statement, oid)
    return buf.getvalue()


def test_flag_unset_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN LIBATTEST_LOG_STMT unset WHEN a statement is logged THEN nothing is emitted and no handler is added."""
    out = _capture(monkeypatch, None, _FakeStmt(), "2.23.133.20.1")
    assert out == ""
    assert not any(getattr(h, "name", None) == "libattest-stmt-log" for h in logging.getLogger("libattest").handlers)


def test_flag_set_renders_pyasn1_prettyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN the flag set and a pyasn1 statement WHEN logged THEN prettyPrint output and the type OID appear on stderr."""
    out = _capture(monkeypatch, "1", _FakeStmt(), "2.23.133.20.1")
    assert "magic=0xff544347" in out
    assert "type=2.23.133.20.1" in out


def test_flag_set_renders_der_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN the flag set and raw DER bytes WHEN logged THEN the byte length and hex appear on stderr."""
    out = _capture(monkeypatch, "1", b"\x30\x03\x02\x01\x07")
    assert "5 bytes" in out
    assert "3003020107" in out


def test_handler_is_not_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN the flag set WHEN a statement is logged twice THEN exactly one tagged stderr handler exists."""
    monkeypatch.setenv("LIBATTEST_LOG_STMT", "1")
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    stmt_log.log_statement("Evidence", _FakeStmt())
    stmt_log.log_statement("Evidence", _FakeStmt())
    tagged = [h for h in logging.getLogger("libattest").handlers if getattr(h, "name", None) == "libattest-stmt-log"]
    assert len(tagged) == 1
