# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

COMPOSE := docker compose -f docker/tpm-demo/docker-compose.yml

help:
	@echo  'Commands:'
	@echo  '  setup              - Set up the python environment (creating env. and install dependencies)'
	@echo  '  setup-dev          - Set up the python environment for development (creating env. and install dependencies, including dev dependencies)'
	@echo  '  unit_tests         - Run all compliance tests.'
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

unit_tests:
	# Run the tests itself.
	python3 -m unittest discover -s tests

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
	python -m pytest docker/tpm-demo/test_demo.py -v