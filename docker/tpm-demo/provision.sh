#!/bin/bash
# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0
#
# Device-side EK provisioning wrapper.  The real work (talking to the TPM,
# marshalling TPM2B_PUBLIC, minting the demo EK cert) is in provision_ek.py --
# this is just a thin CLI entry point so the step reads as "provision" in docs.
#
# Usage:  ./provision.sh [OUT_DIR]      (default OUT_DIR: ./ek-artifacts)
# TCTI is taken from $TCTI (default libtpms:); inside the docker stack it is
# mssim:host=tpmsim,port=2321.
set -euo pipefail

OUT_DIR="${1:-ek-artifacts}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python "${HERE}/provision_ek.py" --out-dir "${OUT_DIR}"
