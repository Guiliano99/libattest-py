# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Audit project OID ownership and references.

The audit records every OID-like value it finds instead of silently excluding
format modules. Format-owned definitions and references are listed separately;
violations outside ``src/libattest/formats`` fail the command. A single finding
can be waived only with an inline, reason-bearing marker::

    value = "1.2.3.4"  # oid-audit: allow - private OID supplied by test protocol

Broad directory exclusions and reason-free waivers are intentionally unsupported.
"""

from __future__ import annotations

import argparse
import ast
import io
import re
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

_OID_PATTERN = re.compile(r"(?<![\d.])(?:[0-2](?:\.[0-9]+){3,})(?![\d.])")
_WAIVER_PATTERN = re.compile(r"#\s*oid-audit:\s*allow\s*-\s*(?P<reason>\S.*)$", re.IGNORECASE)
_FORMATS_PATH = Path("src/libattest/formats")
_DEFAULT_SCAN_PATH = Path("src/libattest")
_DEFAULT_REPORT_PATH = Path("build/oid-access-audit.txt")
_PUBLIC_OID_ACCESSORS = frozenset(
    {
        "get_nonce_request_oid_for_name",
        "get_nonce_response_oid_for_name",
        "get_oid_by_name",
        "get_oid_for_stmt_name",
    }
)


@dataclass(frozen=True, order=True)
class OidOccurrence:
    """One OID-like value found in a Python token."""

    path: str
    line: int
    oid: str
    context: str


@dataclass(frozen=True, order=True)
class OidDefinition:
    """One named OID definition owned by a format module."""

    oid: str
    path: str
    line: int
    name: str


@dataclass(frozen=True, order=True)
class AuditFinding:
    """One policy violation or individually reviewed waiver."""

    path: str
    line: int
    code: str
    detail: str
    waiver_reason: str | None = None


@dataclass(frozen=True)
class AuditResult:
    """Complete OID audit result used by the CLI and unit tests."""

    scanned_files: tuple[str, ...]
    format_definitions: tuple[OidDefinition, ...]
    format_references: tuple[OidOccurrence, ...]
    violations: tuple[AuditFinding, ...]
    waivers: tuple[AuditFinding, ...]


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _is_format_path(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to((root / _FORMATS_PATH).resolve())
    except ValueError:
        return False
    return True


def _iter_python_files(root: Path, paths: Sequence[Path]) -> tuple[Path, ...]:
    files: set[Path] = set()
    for supplied_path in paths:
        path = supplied_path if supplied_path.is_absolute() else root / supplied_path
        if path.is_file() and path.suffix == ".py":
            files.add(path.resolve())
        elif path.is_dir():
            files.update(candidate.resolve() for candidate in path.rglob("*.py") if candidate.is_file())
        else:
            raise FileNotFoundError(f"OID audit path does not exist: {path}")
    return tuple(sorted(files))


def _oid_values(value: str) -> tuple[str, ...]:
    return tuple(match.group(0) for match in _OID_PATTERN.finditer(value))


def _target_names(node: ast.Assign | ast.AnnAssign) -> tuple[str, ...]:
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return tuple(target.id for target in targets if isinstance(target, ast.Name))


def _looks_like_oid_symbol(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.startswith("id_")
        or (lowered.startswith("resolve_") and lowered.endswith("_oid"))
        or _looks_like_public_oid_constant(name)
    )


def _looks_like_public_oid_constant(name: str) -> bool:
    return name.isupper() and bool(re.search(r"(?:^|_)OID(?:_|$)", name))


def _line_waiver(lines: Sequence[str], line: int) -> str | None:
    if line < 1 or line > len(lines):
        return None
    match = _WAIVER_PATTERN.search(lines[line - 1])
    return match.group("reason").strip() if match else None


def _record_finding(
    finding: AuditFinding,
    lines: Sequence[str],
    violations: list[AuditFinding],
    waivers: list[AuditFinding],
) -> None:
    reason = _line_waiver(lines, finding.line)
    if reason:
        waivers.append(
            AuditFinding(
                path=finding.path,
                line=finding.line,
                code=finding.code,
                detail=finding.detail,
                waiver_reason=reason,
            )
        )
    else:
        violations.append(finding)


def _token_occurrences(path: str, source: str) -> tuple[OidOccurrence, ...]:
    occurrences: list[OidOccurrence] = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for token in tokens:
        if token.type not in (tokenize.STRING, tokenize.COMMENT):
            continue
        context = "comment" if token.type == tokenize.COMMENT else "string"
        for oid in _oid_values(token.string):
            occurrences.append(OidOccurrence(path=path, line=token.start[0], oid=oid, context=context))
    return tuple(occurrences)


def _format_definitions(path: str, tree: ast.AST) -> tuple[OidDefinition, ...]:
    definitions: list[OidDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        names = _target_names(node)
        value = node.value
        if value is None:
            continue
        oids = {
            oid
            for child in ast.walk(value)
            if isinstance(child, ast.Constant) and isinstance(child.value, str)
            for oid in _oid_values(child.value)
        }
        for name in names:
            if _looks_like_oid_symbol(name):
                definitions.extend(
                    OidDefinition(oid=oid, path=path, line=node.lineno, name=name) for oid in sorted(oids)
                )
    return tuple(definitions)


def _audit_tree(
    path: str,
    tree: ast.AST,
    lines: Sequence[str],
    violations: list[AuditFinding],
    waivers: list[AuditFinding],
) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("libattest.formats"):
            for alias in node.names:
                is_root_accessor_export = (
                    path == "src/libattest/__init__.py"
                    and node.module == "libattest.formats.stmt_mappings"
                    and alias.name in _PUBLIC_OID_ACCESSORS
                )
                is_direct_accessor_import = alias.name in _PUBLIC_OID_ACCESSORS and not is_root_accessor_export
                if _looks_like_oid_symbol(alias.name) or is_direct_accessor_import:
                    _record_finding(
                        AuditFinding(
                            path=path,
                            line=node.lineno,
                            code="OID002",
                            detail=f"direct format OID import: {node.module}.{alias.name}",
                        ),
                        lines,
                        violations,
                        waivers,
                    )
        elif isinstance(node, ast.Call):
            function = node.func
            name = (
                function.id
                if isinstance(function, ast.Name)
                else function.attr
                if isinstance(function, ast.Attribute)
                else ""
            )
            if name.startswith("resolve_") and name.endswith("_oid"):
                _record_finding(
                    AuditFinding(
                        path=path,
                        line=node.lineno,
                        code="OID003",
                        detail=f"direct format-specific OID resolver call: {name}()",
                    ),
                    lines,
                    violations,
                    waivers,
                )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            names = _target_names(node)
            for name in names:
                if _looks_like_public_oid_constant(name):
                    _record_finding(
                        AuditFinding(
                            path=path,
                            line=node.lineno,
                            code="OID004",
                            detail=f"OID constant outside formats: {name}",
                        ),
                        lines,
                        violations,
                        waivers,
                    )
            if "__all__" in names and node.value is not None:
                for child in ast.walk(node.value):
                    if (
                        isinstance(child, ast.Constant)
                        and isinstance(child.value, str)
                        and _looks_like_oid_symbol(child.value)
                    ):
                        _record_finding(
                            AuditFinding(
                                path=path,
                                line=getattr(child, "lineno", node.lineno),
                                code="OID005",
                                detail=f"raw OID symbol re-export outside formats: {child.value}",
                            ),
                            lines,
                            violations,
                            waivers,
                        )


# The complete report keeps each finding class separate until final immutable aggregation.
def audit_paths(root: Path, paths: Sequence[Path]) -> AuditResult:  # pylint: disable=too-many-locals
    """Audit Python files under *paths* relative to *root*."""
    scanned_files: list[str] = []
    definitions: list[OidDefinition] = []
    format_references: list[OidOccurrence] = []
    violations: list[AuditFinding] = []
    waivers: list[AuditFinding] = []

    for file_path in _iter_python_files(root, paths):
        relative = _relative_path(file_path, root)
        scanned_files.append(relative)
        source = file_path.read_text(encoding="utf-8")
        lines = source.splitlines()
        try:
            tree = ast.parse(source, filename=relative)
            occurrences = _token_occurrences(relative, source)
        except (SyntaxError, tokenize.TokenError) as exc:
            violations.append(
                AuditFinding(
                    path=relative, line=getattr(exc, "lineno", 1) or 1, code="OID000", detail=f"parse failed: {exc}"
                )
            )
            continue

        if _is_format_path(file_path, root):
            definitions.extend(_format_definitions(relative, tree))
            format_references.extend(occurrences)
            continue

        for occurrence in occurrences:
            _record_finding(
                AuditFinding(
                    path=relative,
                    line=occurrence.line,
                    code="OID001",
                    detail=f"dotted-decimal OID outside formats: {occurrence.oid} ({occurrence.context})",
                ),
                lines,
                violations,
                waivers,
            )
        _audit_tree(relative, tree, lines, violations, waivers)

    definitions_by_oid: dict[str, list[OidDefinition]] = {}
    for definition in definitions:
        definitions_by_oid.setdefault(definition.oid, []).append(definition)
    for oid, oid_definitions in definitions_by_oid.items():
        owners = {(item.path, item.name) for item in oid_definitions}
        if len(owners) > 1:
            for definition in oid_definitions:
                violations.append(
                    AuditFinding(
                        path=definition.path,
                        line=definition.line,
                        code="OID006",
                        detail=f"OID {oid} has multiple format definitions: {sorted(owners)}",
                    )
                )

    return AuditResult(
        scanned_files=tuple(sorted(scanned_files)),
        format_definitions=tuple(sorted(set(definitions))),
        format_references=tuple(sorted(set(format_references))),
        violations=tuple(sorted(set(violations))),
        waivers=tuple(sorted(set(waivers))),
    )


def _report_lines(result: AuditResult) -> Iterable[str]:
    yield "OID access audit"
    yield "================"
    yield f"Scanned files: {len(result.scanned_files)}"
    yield f"Format-owned definitions: {len(result.format_definitions)}"
    yield f"Format-local references: {len(result.format_references)}"
    yield f"Reviewed waivers: {len(result.waivers)}"
    yield f"Violations: {len(result.violations)}"
    yield ""

    yield "Format-owned definitions"
    yield "------------------------"
    if result.format_definitions:
        for item in result.format_definitions:
            yield f"{item.path}:{item.line}: {item.name} = {item.oid}"
    else:
        yield "(none)"
    yield ""

    yield "Format-local OID references"
    yield "---------------------------"
    if result.format_references:
        for item in result.format_references:
            yield f"{item.path}:{item.line}: {item.oid} ({item.context})"
    else:
        yield "(none)"
    yield ""

    yield "Individually reviewed waivers"
    yield "-----------------------------"
    if result.waivers:
        for item in result.waivers:
            yield f"{item.path}:{item.line}: {item.code}: {item.detail} [reason: {item.waiver_reason}]"
    else:
        yield "(none)"
    yield ""

    yield "Violations"
    yield "----------"
    if result.violations:
        for item in result.violations:
            yield f"{item.path}:{item.line}: {item.code}: {item.detail}"
    else:
        yield "(none)"


def write_report(result: AuditResult, report_path: Path) -> None:
    """Write the complete audit *result* to *report_path*."""
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(_report_lines(result)) + "\n", encoding="utf-8")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[_DEFAULT_SCAN_PATH],
        help="Python file or directory to scan (default: src/libattest)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=_DEFAULT_REPORT_PATH,
        help="complete findings report (default: build/oid-access-audit.txt)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the OID audit CLI and return a process exit status."""
    args = _parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    result = audit_paths(root, args.paths)
    report_path = args.report if args.report.is_absolute() else root / args.report
    write_report(result, report_path)
    print(
        f"OID audit: {len(result.scanned_files)} files, "
        f"{len(result.format_definitions)} definitions, "
        f"{len(result.waivers)} waivers, {len(result.violations)} violations"
    )
    print(f"Complete report: {report_path}")
    return 1 if result.violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
