# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Well-known deterministic values for the TCG TPM 2.0 reference simulator.

The TCG simulator (mssim, ``github.com/TrustedComputingGroup/TPM``) starts
with all PCRs in every bank initialised to their reset value after
``TPM2_Startup(CLEAR)``.  None of the provisioning steps in this repo
(``tpm2_createprimary``, ``tpm2_createek``, ``tpm2_createak``,
``tpm2_evictcontrol``, ``tpm2_readpublic``) extend a PCR, so for the standard
PCR selection used by ``provision.sh`` the resulting ``pcrDigest`` is bit-
for-bit identical on every clean simulator boot.

This module pins those values as Python constants so tests can:

* Assert against a known reference without first capturing it dynamically.
* Compare two test runs for byte-identity.
* Detect regressions (any change in the simulator's reset state or in our
  PCR selection will trip the constants and fail the test).

The values were verified empirically (2026-04-29) by spinning up the
simulator three times via ``docker compose`` and reading the SHA-256 PCR
bank PCRs 0–7 each time:

* Run 1, 2, 3 all returned the same digest.
* The digest matched the theoretical
  ``hashlib.sha256(b"\\x00" * 256).digest()``.

If any of these assumptions changes (a future provisioning step extends a
PCR, or you pick a different selection / bank) the constants below become
stale.  Re-run :func:`libattest.simulator.tpm_client.TpmClient.pcr_digest`
on a known-good run and update.
"""

from __future__ import annotations

import hashlib

#: Hash algorithm of the bank used for the canonical pcrDigest.
SIMULATOR_PCR_BANK: str = "sha256"

#: PCR selection string passed to ``tpm2_pcrread`` and embedded in the
#: ``TPMS_QUOTE_INFO.pcrSelect``.  Matches what ``provision.sh`` baselines.
SIMULATOR_PCR_DEFAULT_SELECTION: str = "sha256:0,1,2,3,4,5,6,7"

#: Reset value of a single PCR in the SHA-256 bank after ``TPM2_Startup(CLEAR)``.
SIMULATOR_PCR_RESET_VALUE: bytes = b"\x00" * 32

#: ``pcrDigest = H_alg( PCR0 || PCR1 || ... || PCRn )`` for the default
#: selection above, computed over the reset state.  Verified empirically.
SIMULATOR_ZERO_PCR_DIGEST: bytes = hashlib.sha256(SIMULATOR_PCR_RESET_VALUE * 8).digest()

#: Hex string form of :data:`SIMULATOR_ZERO_PCR_DIGEST` for use in JSON
#: ``pcr_reference.json`` files (matches ``expected_pcr_digest_hex`` schema).
SIMULATOR_ZERO_PCR_DIGEST_HEX: str = SIMULATOR_ZERO_PCR_DIGEST.hex()
