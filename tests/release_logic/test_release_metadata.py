# SPDX-FileCopyrightText: Copyright 2026
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the release metadata helper script."""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


def _load_release_metadata_module() -> ModuleType:
    """Load `scripts/release/release_metadata.py` as a testable module."""
    module_path = Path(__file__).resolve().parents[2] / "scripts" / "release" / "release_metadata.py"
    spec = importlib.util.spec_from_file_location("release_metadata", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load release_metadata module specification.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_metadata = _load_release_metadata_module()


class TestReleaseMetadata(unittest.TestCase):
    """Test cases for release metadata script commands."""

    def setUp(self) -> None:
        """Create an isolated workspace for each test case."""
        self.temp_path = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp_path)
        self.pyproject_path = self.temp_path / "pyproject.toml"
        self.changelog_path = self.temp_path / "CHANGELOG.md"
        self.github_output_path = self.temp_path / "github_output.txt"

    def _write_pyproject(self, version: str) -> None:
        """Write a minimal pyproject file with a configurable version."""
        self.pyproject_path.write_text(
            f'[project]\nname = "default-package"\nversion = "{version}"\n',
            encoding="utf-8",
        )

    def _write_changelog(self, content: str) -> None:
        """Write changelog content used by command tests."""
        self.changelog_path.write_text(content, encoding="utf-8")

    def _read_github_output(self) -> dict[str, str]:
        """Parse key-value pairs from the simulated GitHub output file."""
        pairs: dict[str, str] = {}
        for line in self.github_output_path.read_text(encoding="utf-8").splitlines():
            key, value = line.split("=", maxsplit=1)
            pairs[key] = value
        return pairs

    def test_resolve_version_writes_expected_outputs(self) -> None:
        """
        Validate resolve-version success path.

        GIVEN valid pyproject and changelog data.
        WHEN resolve-version is executed.
        THEN the command succeeds and writes expected GitHub outputs.
        """
        self._write_pyproject("1.2.3")
        self._write_changelog("# 1.2.3\n\n- Added release metadata helper.\n")

        exit_code = release_metadata.main(
            [
                "resolve-version",
                "--pyproject",
                str(self.pyproject_path),
                "--changelog",
                str(self.changelog_path),
                "--github-output",
                str(self.github_output_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            self._read_github_output(),
            {
                "project_version": "1.2.3",
                "version": "1.2.3",
                "tag": "v1.2.3",
            },
        )

    def test_resolve_version_fails_for_mismatched_input_version(self) -> None:
        """
        Validate resolve-version mismatch handling.

        GIVEN pyproject version and mismatched input version.
        WHEN resolve-version is executed.
        THEN the command returns an error code.
        """
        self._write_pyproject("1.2.3")
        self._write_changelog("# 1.2.3\n\n- Added release metadata helper.\n")

        exit_code = release_metadata.main(
            [
                "resolve-version",
                "--input-version",
                "1.2.4",
                "--pyproject",
                str(self.pyproject_path),
                "--changelog",
                str(self.changelog_path),
                "--github-output",
                str(self.github_output_path),
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertFalse(self.github_output_path.exists())

    def test_validate_tag_writes_expected_outputs(self) -> None:
        """
        Validate validate-tag success path.

        GIVEN a valid release tag and matching project metadata.
        WHEN validate-tag is executed.
        THEN the command succeeds and writes tag outputs.
        """
        self._write_pyproject("2.0.0")
        self._write_changelog("# 2.0.0\n\n- Important release.\n")

        exit_code = release_metadata.main(
            [
                "validate-tag",
                "--tag-name",
                "v2.0.0",
                "--pyproject",
                str(self.pyproject_path),
                "--changelog",
                str(self.changelog_path),
                "--github-output",
                str(self.github_output_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            self._read_github_output(),
            {
                "tag_name": "v2.0.0",
                "tag_version": "2.0.0",
            },
        )

    def test_validate_tag_fails_for_missing_v_prefix(self) -> None:
        """
        Validate validate-tag prefix validation.

        GIVEN a tag that does not start with v.
        WHEN validate-tag is executed.
        THEN the command returns an error code.
        """
        self._write_pyproject("2.0.0")
        self._write_changelog("# 2.0.0\n\n- Important release.\n")

        exit_code = release_metadata.main(
            [
                "validate-tag",
                "--tag-name",
                "2.0.0",
                "--pyproject",
                str(self.pyproject_path),
                "--changelog",
                str(self.changelog_path),
                "--github-output",
                str(self.github_output_path),
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertFalse(self.github_output_path.exists())

    def test_write_release_notes_extracts_requested_section(self) -> None:
        """
        Validate release note extraction for one version.

        GIVEN a changelog containing multiple versions.
        WHEN write-release-notes is executed for one version.
        THEN only that version notes are written to output.
        """
        self._write_changelog(
            "# 2.1.0\n\n- Added release pipeline docs.\n- Improved checks.\n\n# 2.0.0\n\n- Previous release.\n"
        )
        output_path = self.temp_path / "RELEASE_NOTES.md"

        exit_code = release_metadata.main(
            [
                "write-release-notes",
                "--version",
                "2.1.0",
                "--changelog",
                str(self.changelog_path),
                "--output",
                str(output_path),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            output_path.read_text(encoding="utf-8"), "- Added release pipeline docs.\n- Improved checks.\n"
        )

    def test_write_release_notes_fails_when_version_has_no_notes(self) -> None:
        """
        Validate release note extraction failure for empty section.

        GIVEN a changelog heading with no content under it.
        WHEN write-release-notes is executed for that version.
        THEN the command returns an error code.
        """
        self._write_changelog("# 3.0.0\n# 2.9.9\n\n- Previous release.\n")
        output_path = self.temp_path / "RELEASE_NOTES.md"

        exit_code = release_metadata.main(
            [
                "write-release-notes",
                "--version",
                "3.0.0",
                "--changelog",
                str(self.changelog_path),
                "--output",
                str(output_path),
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
