# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM simulator helpers for testing the TPM verifier backend.

This subpackage gives developers a Python-side handle on the docker-compose
stack used by ``attestation-attester/tpm-platform-attest`` so they can:

* Spin the simulator + verifier services up and down from a test
  (:class:`SimulatorStack`).
* Drive ``tpm2-tools`` against the simulator inside the container
  (:class:`TpmClient`).
* Talk to the Veraison challenge-response API of ``tpm-verifier``
  (:class:`VerifierClient`).

The intent is *not* to replace ``e2e-test.sh`` — it is to give pytest-style
tests a way to write focused checks against the running stack (e.g. "submit
this exact bundle and assert the verifier returns ``contraindicated``").

Well-known constants for the simulator's deterministic boot state live in
:mod:`libattest.simulator.constants`.

Example
-------

.. code-block:: python

    from libattest.simulator import (
        SimulatorStack, TpmClient, VerifierClient,
        SIMULATOR_ZERO_PCR_DIGEST,
    )

    with SimulatorStack() as stack:
        stack.up(["simulator", "tpm-verifier"])
        stack.wait_healthy("tpm-verifier")
        tpm = TpmClient(stack)
        digest = tpm.pcr_digest()
        assert digest == SIMULATOR_ZERO_PCR_DIGEST
"""

from libattest.simulator.constants import (
    SIMULATOR_PCR_BANK,
    SIMULATOR_PCR_DEFAULT_SELECTION,
    SIMULATOR_PCR_RESET_VALUE,
    SIMULATOR_ZERO_PCR_DIGEST,
    SIMULATOR_ZERO_PCR_DIGEST_HEX,
)
from libattest.simulator.docker_stack import SimulatorStack
from libattest.simulator.tpm_client import TpmClient
from libattest.simulator.verifier_client import VerifierClient

__all__ = [
    "SIMULATOR_PCR_BANK",
    "SIMULATOR_PCR_DEFAULT_SELECTION",
    "SIMULATOR_PCR_RESET_VALUE",
    "SIMULATOR_ZERO_PCR_DIGEST",
    "SIMULATOR_ZERO_PCR_DIGEST_HEX",
    "SimulatorStack",
    "TpmClient",
    "VerifierClient",
]
