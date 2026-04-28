# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

help:
	@echo  'Commands:'
	@echo  '  setup              - Set up the python environment (creating env. and install dependencies)'
	@echo  '  setup-dev          - Set up the python environment for development (creating env. and install dependencies, including dev dependencies)'
	@echo  '  unit_tests         - Run all compliance tests.'
	@echo  '  show-outdated      - Show outdated python dependencies.'

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