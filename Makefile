# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

COMPOSE := docker compose -f docker/tpm-demo/docker-compose.yml
SE05X_COMPOSE := docker compose -f docker/se05x-demo/docker-compose.yml
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

help:
	@echo  'Commands:'
	@echo  '  setup              - Set up the python environment (creating env. and install dependencies)'
	@echo  '  setup-dev          - Set up the python environment for development (creating env. and install dependencies, including dev dependencies)'
	@echo  '  unit_tests         - Run all compliance tests.'
	@echo  '  check-oids         - Audit centralized OID ownership and references.'
	@echo  '  show-outdated      - Show outdated python dependencies.'
	@echo  ''
	@echo  'TPM attestation tests (Docker — no local TPM libraries needed):'
	@echo  '  tpm-build          - Build the tpmsim + client Docker images.'
	@echo  '  tpm-test           - Run TPM attestation tests via Docker.'
	@echo  '  tpm-demo           - Run the platform + key attestation demos via Docker.'
	@echo  '  tpm-shell          - Open an interactive shell in the client container.'
	@echo  '  tpm-down           - Stop and remove the simulator stack.'
	@echo  ''
	@echo  'TPM attestation tests (local — requires libtss2-dev + tpm2-pytss):'
	@echo  '  tpm-test-local     - Run TPM attestation tests using the local libtpms TCTI.'
	@echo  ''
	@echo  'SE05x attestation demo (Docker; builds the GPL simulator locally, never push it):'
	@echo  '  se05x-build        - Build the se05xsim + client Docker images.'
	@echo  '  se05x-test         - Run the live SE05x tests and the key-per-start check.'
	@echo  '  se05x-demo         - Run the narrated SE05x RA flow via Docker.'
	@echo  '  se05x-down         - Stop the SE05x stack and remove its trust volume.'

unit_tests:
	# Run the tests itself (pytest collects the pytest-style suite; unittest discover did not).
	$(PYTHON) -m pytest tests

check-oids:
	$(PYTHON) scripts/check_oid_access.py

setup:
	@echo "Setting up the python environment..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh

setup-dev:
	@echo "Setting up the python environment for development (including dev dependencies)..."
	chmod +x scripts/setup.sh
	./scripts/setup.sh dev=1

show-outdated:
	@echo "Showing outdated dependencies..."
	uv tree --outdated --depth 1

start-app:
	@echo "Start the web interface"

# ── TPM attestation tests via Docker (no local TPM library install needed) ──

tpm-build:
	$(COMPOSE) build

tpm-test: tpm-build
	$(COMPOSE) run --rm test

tpm-demo: tpm-build
	$(COMPOSE) run --rm demo

tpm-shell: tpm-build
	$(COMPOSE) run --rm client

tpm-down:
	$(COMPOSE) down -v

# ── TPM attestation tests using the local libtpms TCTI ──────────────────────
# Requires: sudo apt install libtss2-dev libtss2-tcti-libtpms0
#           pip install 'tpm2-pytss>=2.3.0'

tpm-test-local:
	PYTHONPATH=src $(PYTHON) -m pytest docker/tpm-demo/test_demo.py -v

# ── SE05x attestation demo via Docker (patched wolfSSL SE050 simulator) ─────
# The key-per-start check runs on the host: it starts its own simulators on
# free 127.0.0.1 ports and reads their attestation keys.

se05x-build:
	$(SE05X_COMPOSE) build

se05x-test: se05x-build
	$(SE05X_COMPOSE) run --rm test
	PYTHONPATH=src $(PYTHON) docker/se05x-demo/check_key_per_start.py

se05x-demo: se05x-build
	$(SE05X_COMPOSE) run --rm demo

se05x-down:
	$(SE05X_COMPOSE) down -v
