<!--
SPDX-FileCopyrightText: Copyright 2025

SPDX-License-Identifier: Apache-2.0
-->
# DefaultPy — Python Package Template

A default Python project template with a pre-configured CI/CD pipeline, linting, type checking, license compliance, and pre-commit hooks.

## Template Checklist

When using this repository as a template for a new Python package, update the following files and values.

---

### 1. `pyproject.toml`

This is the central configuration file for your package.

| Field | What to change |
|---|---|
| `name` | Your package name (e.g. `"my-package"`) |
| `version` | Starting version (e.g. `"0.1.0"`) |
| `description` | A short description of your package |
| `authors[].name` | Your name or your organisation's name |
| `authors[].email` | The contact e-mail address |
| `requires-python` | Minimum Python version you target |
| `dependencies` | Add your runtime dependencies here |
| SPDX copyright year | Update `Copyright 2025` to the current year |

---

### 2. `CHANGELOG.md`

Add an entry for every released version. The value in `pyproject.toml` (`project.version`) should match a heading in `CHANGELOG.md`. The expected format is:

```markdown
# 0.1.0

- Initial release
```

---

### 3. Source code under `src/`

The template ships with a single `src/__init__.py` as a placeholder.

- Create your actual package directory inside `src/` (e.g. `src/my_package/`).
- Replace or remove `main.py` with your own entry point if needed.
- Update the tests in `tests/` to cover your code.

---

### 4. `ruff.toml`

| Field | What to change |
|---|---|
| `lint.isort.known-first-party` | Replace `"src"` with your package name (e.g. `"my_package"`) |
| SPDX copyright year | Update `Copyright 2026` to the current year |

---

### 5. `REUSE.toml`

Keeps track of copyright and licensing metadata for REUSE compliance.

| Field | What to change |
|---|---|
| `SPDX-PackageName` | Your package name |
| `SPDX-PackageDownloadLocation` | URL where the package can be downloaded (e.g. PyPI or a git remote) |
| `SPDX-FileCopyrightText` | Update the copyright year |
| `path` list | Add or remove paths that should carry this copyright annotation |

---

### 6. `LICENSES/`

The template is licensed under Apache-2.0. If you use a different licence:

1. Replace the licence file in `LICENSES/` with the appropriate SPDX licence text.
2. Update the `license` field in `pyproject.toml`.
3. Update the `SPDX-License-Identifier` header in every source file.
4. Update `REUSE.toml` accordingly.

If you keep Apache-2.0, just update the copyright year in the `LICENSE` file.

---

### 7. `.pre-commit-config.yaml`

| Field | What to change |
|---|---|
| `pyupgrade` entry argument | Change `--py311-plus` to match your minimum Python version (e.g. `--py313-plus`) |

Install the hooks once after cloning:

```bash
pip install pre-commit
pre-commit install
```

---

### 8. GitHub Actions — `.github/workflows/check_quality.yml`

| Field | What to change |
|---|---|
| `env.PYTHON_VERSION` | Set to the Python version your project targets (e.g. `"3.13"`) |
| `pylint` job — `run` command | Replace `src` with the directory/package pylint should analyse |
| `unit_test` job — `-s tests` | Replace `tests` with the name of your test directory if different |
| `OQS_INSTALL_PATH` env var | Remove if your tests do not use it |
| `codespell` `--skip` pattern | Adjust the skip list to match paths in your repository |

---

### 9. GitLab CI — `.gitlab-ci.yml`

| Field | What to change |
|---|---|
| `variables.PYTHON_VERSION` | Set to your target Python version |
| `setup_env` tags | Replace `[shell]` with your GitLab runner tag, or remove the `tags:` key for shared runners |
| `pylint` job — script | Replace `resources` with the directory pylint should analyse |
| `unit_test` job — script | Replace `unit_tests` with your test directory |
| `OQS_INSTALL_PATH` env var | Remove if unused |
| `codespell` `--skip` pattern | Adjust to match your repository layout |

---

### 9.1 Release Pipelines — GitHub + GitLab only

This template now includes two release workflows under `.github/workflows/`:

1. `create_release_tag.yml`
2. `release_on_tag.yml`

The release flow is intentionally split into two parts so each step is explicit and easy to understand.

Release validation and metadata extraction are implemented in Python at `scripts/release/release_metadata.py`.
This keeps version/tag/changelog checks out of workflow YAML and gives both workflows a shared logic source.

#### Workflow A: Create a release tag

File: `.github/workflows/create_release_tag.yml`

- Trigger: `workflow_dispatch` (manual run from GitHub Actions UI).
- Reads `project.version` from `pyproject.toml`.
- Validates that `CHANGELOG.md` contains a matching heading.
- Creates and pushes an annotated tag in the format `vX.Y.Z`.

#### Workflow B: Publish the release

File: `.github/workflows/release_on_tag.yml`

- Trigger: push of `v*.*.*` tags.
- Validates the pushed tag version against `pyproject.toml`.
- Extracts release notes from the matching section in `CHANGELOG.md`.
- Creates a GitHub Release.
- Creates or updates a GitLab Release for the same tag.

#### Required repository settings

In GitHub repository settings, configure:

- Secret: `GITLAB_TOKEN` (token with API access to the target GitLab project)
- Variable: `GITLAB_PROJECT_ID` (numeric GitLab project ID)
- Optional variable: `GITLAB_API_URL` (defaults to `https://gitlab.com/api/v4`)

The pipeline publishes releases only to GitHub and GitLab. It does not publish packages to registries like PyPI.

---

### 10. Copyright headers in source files

Every file tracked by REUSE must carry an SPDX header. Update the year in the `SPDX-FileCopyrightText` lines across all files. The `scripts/add_licenses.py` helper script can assist with adding headers to new files.

---

## Development Setup

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install the package with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Running Checks Locally

```bash
# Lint
ruff check

# Format
ruff format

# Type check
pyright

# License compliance
reuse lint

# Spell check
codespell .

# Unit tests
make unit_tests
```
