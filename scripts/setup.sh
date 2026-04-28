#!/bin/bash
# This script sets up a Python virtual environment and installs all dependencies
# needed to run the CMP test suite. It uses 'uv' as a fast package installer/resolver.
#
# Usage:
#   ./scripts/setup.sh          # Install normal dependencies only
#   ./scripts/setup.sh dev=1    # Also install developer tools (linters, type checkers, etc.)

# Exit immediately if any command fails (instead of silently continuing)
set -e

# Check for dev argument
# Loop over all arguments passed to the script and look for "dev=1"
INSTALL_DEV=0
for arg in "$@"; do
    if [ "$arg" == "dev=1" ]; then
        INSTALL_DEV=1
    fi
done

# Define the virtual environment directory
# A virtual environment isolates Python packages from the system Python installation
VENV_DIR=".venv"

# Check if .venv exists
# -d tests whether the path is an existing directory
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment in $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists in $VENV_DIR."
fi

# Activate the virtual environment
# This makes 'python3' and 'pip' commands inside this shell session point to
# the isolated environment in .venv/ instead of the system-wide Python
source "$VENV_DIR/bin/activate"

# Update pip
# pip is the standard Python package manager; keeping it up to date avoids warnings
echo "Upgrading pip..."
pip install --upgrade pip

# Install or update uv
# 'command -v uv' checks whether the 'uv' binary is on the PATH
# uv is a fast Rust-based Python package manager used to resolve and install dependencies
if ! command -v uv &> /dev/null; then
    echo "uv not found, installing uv via pip..."
    pip install uv
else
    # uv is already installed — update it via pip to the latest version.
    # We intentionally avoid 'uv self update' here because that command only works
    # when uv was installed via the standalone installer script (not via pip).
    # Since we activate the .venv above, the 'uv' on PATH is the pip-installed copy
    # inside .venv, so upgrading it through pip is always safe and portable.
    echo "uv already installed, updating via pip..."
    pip install --upgrade uv
fi

# Use uv sync to install packages defined in pyproject.toml
# 'uv sync' reads pyproject.toml and installs exactly the packages listed there
# --all-extras also installs optional dependency groups (e.g. 'dev', 'pq')
if [ "$INSTALL_DEV" -eq 1 ]; then
    echo "Running uv sync with all extras (dev)..."
    uv sync --all-extras
else
    echo "Running uv sync..."
    uv sync
fi

echo "Setup complete. Virtual environment is ready."
# The virtual environment is only active for the current shell session.
# New terminal sessions need to activate it again manually with the command below.
echo "To activate it, run: source $VENV_DIR/bin/activate"

