# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Centralized release metadata helpers for GitHub/GitLab workflows.

This script keeps release/version validation logic outside CI YAML files.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$")


def _read_project_version(pyproject_path: Path) -> str:
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = data.get("project", {})
    version = project.get("version", "")
    if not isinstance(version, str) or not version:
        raise ValueError("Could not read project.version from pyproject.toml")
    return version


def _has_changelog_heading(changelog_path: Path, version: str) -> bool:
    heading = f"# {version}"
    return any(line.strip() == heading for line in changelog_path.read_text(encoding="utf-8").splitlines())


def _extract_release_notes(changelog_path: Path, version: str) -> str:
    start_heading = f"# {version}"
    lines = changelog_path.read_text(encoding="utf-8").splitlines()

    capture = False
    collected: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped == start_heading:
            capture = True
            continue
        if capture and stripped.startswith("# "):
            break
        if capture:
            collected.append(line)

    notes = "\n".join(collected).strip()
    if not notes:
        raise ValueError(f"No release notes found under '# {version}' in CHANGELOG.md")
    return f"{notes}\n"


def _write_github_output(pairs: dict[str, str], github_output: str | None) -> None:
    if not github_output:
        return
    with open(github_output, "a", encoding="utf-8") as out_file:
        for key, value in pairs.items():
            out_file.write(f"{key}={value}\n")


def _cmd_resolve_version(args: argparse.Namespace) -> int:
    pyproject_path = Path(args.pyproject)
    changelog_path = Path(args.changelog)

    project_version = _read_project_version(pyproject_path)
    target_version = args.input_version or project_version

    if not SEMVER_RE.fullmatch(target_version):
        raise ValueError("Version must look like semantic versioning, e.g. 1.2.3 or 1.2.3-rc.1")

    if target_version != project_version:
        raise ValueError(f"Input version '{target_version}' does not match pyproject.toml version '{project_version}'.")

    if not _has_changelog_heading(changelog_path, target_version):
        raise ValueError(f"CHANGELOG.md does not contain heading '# {target_version}'.")

    _write_github_output(
        {
            "project_version": project_version,
            "version": target_version,
            "tag": f"v{target_version}",
        },
        args.github_output,
    )

    return 0


def _cmd_validate_tag(args: argparse.Namespace) -> int:
    pyproject_path = Path(args.pyproject)
    changelog_path = Path(args.changelog)

    tag_name = args.tag_name
    if not tag_name:
        raise ValueError("Missing tag name. Provide --tag-name or set GITHUB_REF_NAME.")
    if not tag_name.startswith("v"):
        raise ValueError(f"Tag '{tag_name}' must start with 'v'.")

    tag_version = tag_name[1:]
    if not SEMVER_RE.fullmatch(tag_version):
        raise ValueError(f"Tag version '{tag_version}' is not a valid semantic version.")

    project_version = _read_project_version(pyproject_path)
    if tag_version != project_version:
        raise ValueError(f"Tag version '{tag_version}' does not match pyproject.toml version '{project_version}'.")

    if not _has_changelog_heading(changelog_path, project_version):
        raise ValueError(f"CHANGELOG.md does not contain heading '# {project_version}'.")

    _write_github_output(
        {
            "tag_name": tag_name,
            "tag_version": tag_version,
        },
        args.github_output,
    )

    return 0


def _cmd_write_release_notes(args: argparse.Namespace) -> int:
    changelog_path = Path(args.changelog)
    output_path = Path(args.output)

    version = args.version
    if not version:
        raise ValueError("Missing version. Provide --version to extract release notes.")

    notes = _extract_release_notes(changelog_path, version)
    output_path.write_text(notes, encoding="utf-8")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the command-line parser for release metadata actions."""
    parser = argparse.ArgumentParser(description="Release metadata helper for CI workflows")
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_parser = subparsers.add_parser("resolve-version", help="Resolve and validate release version")
    resolve_parser.add_argument("--input-version", default="", help="Optional version provided by workflow input")
    resolve_parser.add_argument("--pyproject", default="pyproject.toml", help="Path to pyproject.toml")
    resolve_parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to changelog")
    resolve_parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    resolve_parser.set_defaults(func=_cmd_resolve_version)

    validate_parser = subparsers.add_parser("validate-tag", help="Validate pushed tag against project metadata")
    validate_parser.add_argument("--tag-name", default=os.environ.get("GITHUB_REF_NAME", ""))
    validate_parser.add_argument("--pyproject", default="pyproject.toml", help="Path to pyproject.toml")
    validate_parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to changelog")
    validate_parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    validate_parser.set_defaults(func=_cmd_validate_tag)

    notes_parser = subparsers.add_parser("write-release-notes", help="Write release notes for a version")
    notes_parser.add_argument("--version", required=True, help="Version to extract from changelog")
    notes_parser.add_argument("--changelog", default="CHANGELOG.md", help="Path to changelog")
    notes_parser.add_argument("--output", default="RELEASE_NOTES.md", help="Output release notes path")
    notes_parser.set_defaults(func=_cmd_write_release_notes)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the release metadata command-line interface.

    :param argv: Optional command arguments. If omitted, arguments are read from `sys.argv`.
    :return: Exit status code (0 for success, 1 for validation failure).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.func(args)
    except ValueError as exc:
        print(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
