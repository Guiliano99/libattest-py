# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Tests for the repository OID access audit."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load_oid_audit_module() -> ModuleType:
    """Load ``scripts/check_oid_access.py`` as a testable module."""
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "check_oid_access.py"
    spec = importlib.util.spec_from_file_location("check_oid_access", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load check_oid_access module specification")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_audit_reports_and_saves_outside_format_oid(tmp_path: Path) -> None:
    """GIVEN a raw OID outside formats WHEN audited THEN it fails and is saved in the report."""
    audit = _load_oid_audit_module()
    source = tmp_path / "src" / "libattest" / "ra" / "profile.py"
    source.parent.mkdir(parents=True)
    source.write_text('PROFILE_OID = "1.2.3.4"\n', encoding="utf-8")

    result = audit.audit_paths(tmp_path, [Path("src/libattest")])
    report = tmp_path / "build" / "oid-access-audit.txt"
    audit.write_report(result, report)

    assert {finding.code for finding in result.violations} == {"OID001", "OID004"}
    assert "src/libattest/ra/profile.py:1" in report.read_text(encoding="utf-8")
    assert "1.2.3.4" in report.read_text(encoding="utf-8")


def test_audit_lists_format_definitions_instead_of_ignoring_them(tmp_path: Path) -> None:
    """GIVEN a format-owned OID WHEN audited THEN its definition and reference are reported."""
    audit = _load_oid_audit_module()
    source = tmp_path / "src" / "libattest" / "formats" / "demo.py"
    source.parent.mkdir(parents=True)
    source.write_text('DEMO_OID = "1.2.3.4"\n', encoding="utf-8")

    result = audit.audit_paths(tmp_path, [Path("src/libattest")])

    assert result.violations == ()
    assert [(item.name, item.oid) for item in result.format_definitions] == [("DEMO_OID", "1.2.3.4")]
    assert [(item.oid, item.context) for item in result.format_references] == [("1.2.3.4", "string")]


def test_audit_rejects_duplicate_format_definitions(tmp_path: Path) -> None:
    """GIVEN two format owners for one OID WHEN audited THEN every duplicate owner is identified."""
    audit = _load_oid_audit_module()
    formats = tmp_path / "src" / "libattest" / "formats"
    formats.mkdir(parents=True)
    (formats / "first.py").write_text('FIRST_OID = "1.2.3.4"\n', encoding="utf-8")
    (formats / "second.py").write_text('SECOND_OID = "1.2.3.4"\n', encoding="utf-8")

    result = audit.audit_paths(tmp_path, [Path("src/libattest")])

    duplicate_findings = [finding for finding in result.violations if finding.code == "OID006"]
    assert len(duplicate_findings) == 2
    assert {finding.path for finding in duplicate_findings} == {
        "src/libattest/formats/first.py",
        "src/libattest/formats/second.py",
    }


def test_audit_rejects_direct_format_oid_access_and_reexport(tmp_path: Path) -> None:
    """GIVEN raw format OID access WHEN audited THEN imports, resolvers, and re-exports all fail."""
    audit = _load_oid_audit_module()
    source = tmp_path / "src" / "libattest" / "verifier" / "bad.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            (
                "from libattest.formats.cmw import ID_PE_CMW",
                "from libattest.formats.key_attest_pop import resolve_key_attest_evidence_oid",
                "from libattest.formats.stmt_mappings import get_oid_by_name",
                "VALUE = resolve_key_attest_evidence_oid()",
                '__all__ = ["ID_PE_CMW"]',
            )
        ),
        encoding="utf-8",
    )

    result = audit.audit_paths(tmp_path, [Path("src/libattest")])

    codes = [finding.code for finding in result.violations]
    assert codes.count("OID002") == 3
    assert codes.count("OID003") == 1
    assert codes.count("OID005") == 1


def test_audit_records_individual_reasoned_waiver(tmp_path: Path) -> None:
    """GIVEN a reasoned one-line waiver WHEN audited THEN it is reported rather than silently ignored."""
    audit = _load_oid_audit_module()
    source = tmp_path / "src" / "libattest" / "testing" / "private.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        'private_oid = "1.2.3.4"  # oid-audit: allow - caller-owned private test OID\n',
        encoding="utf-8",
    )

    result = audit.audit_paths(tmp_path, [Path("src/libattest")])

    assert result.violations == ()
    assert len(result.waivers) == 1
    assert result.waivers[0].waiver_reason == "caller-owned private test OID"
