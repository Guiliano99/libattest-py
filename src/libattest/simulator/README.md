# `libattest.simulator` — TPM simulator helpers for tests

This subpackage exposes the docker-compose stack used by
`attestation-attester/tpm-platform-attest/` to Python tests, so developers
can drive the TPM simulator and the Veraison-API verifier from pytest
without re-creating the whole `e2e-test.sh` shell harness.

## What's in here

| Module                                | What it gives you                                                                                          |
|---------------------------------------|------------------------------------------------------------------------------------------------------------|
| `libattest.simulator.constants`       | Deterministic well-known values: `SIMULATOR_ZERO_PCR_DIGEST`, default selection, reset value.              |
| `libattest.simulator.docker_stack`    | `SimulatorStack` — context manager around `docker compose up/down/exec/logs`.                              |
| `libattest.simulator.tpm_client`      | `TpmClient` — drives `tpm2-tools` (startup, `tpm2_pcrread`, `tpm2_pcrextend`) inside a stack service.      |
| `libattest.simulator.verifier_client` | `VerifierClient` — HTTP client for Veraison `newSession` / submit / `ear-verification-key`.                |

## Why it exists

`e2e-test.sh` covers the happy-path acceptance gates from `constraint.md`,
but it is shell + grep, awkward for fine-grained assertions like "did the
verifier receive exactly one quote statement?" or "what does the verifier
return when we submit a bundle with a swapped tpmTPublic?".  This package
gives those tests a Python surface area, while reusing the *same* docker
images, simulator, and verifier that the end-to-end flow uses — no
parallel reimplementation of TPM operations.

## Requirements

* `docker` CLI on PATH.
* The `tpm-platform-attest` images already built (run
  `docker compose build` once before invoking tests).
* `requests` and `cryptography` (already declared in `pyproject.toml`).

## Quick start

```python
from libattest.simulator import (
    SimulatorStack,
    TpmClient,
    VerifierClient,
    SIMULATOR_ZERO_PCR_DIGEST,
)

def test_simulator_pcr_state_is_deterministic():
    with SimulatorStack() as stack:
        stack.up(["simulator"])
        stack.wait_healthy("simulator")

        tpm = TpmClient(stack, service="provisioner")
        tpm.startup_clear()
        digest = tpm.pcr_digest()                      # SHA-256 PCRs 0-7

        # The simulator's reset state hashes to a well-known constant.
        assert digest == SIMULATOR_ZERO_PCR_DIGEST


def test_verifier_round_trip():
    with SimulatorStack() as stack:
        stack.up(["simulator", "tpm-verifier"])
        stack.wait_healthy("tpm-verifier")

        client = VerifierClient("http://localhost:8444")
        session = client.new_session(nonce_size=32)
        assert len(session.nonce) == 32
        assert session.session_url.startswith("http://localhost:8444")

        # Submitting nothing must NOT produce an "affirming" verdict.
        # (Real tests would build an AttestationBundle here.)
```

## Determinism of the simulator's reset PCR state

The TCG simulator after `TPM2_Startup(CLEAR)` resets every PCR in the
SHA-256 bank to 32 bytes of `0x00`.  None of the provisioning steps
(`tpm2_createprimary`, `tpm2_createek`, `tpm2_createak`,
`tpm2_evictcontrol`, `tpm2_readpublic`) extend a PCR.  Therefore for the
default selection used in this repo (`sha256:0,1,2,3,4,5,6,7`) the
resulting `pcrDigest` is bit-for-bit identical on every clean simulator
boot:

```
pcrDigest = SHA-256( 0x00 * 256 ) = 5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1
```

This was verified empirically (2026-04-29) by running `docker compose up
simulator` three times in succession, reading PCRs 0–7 each time, and
comparing.  All three runs produced the same digest, matching the
theoretical computation.

`SIMULATOR_ZERO_PCR_DIGEST` and `SIMULATOR_ZERO_PCR_DIGEST_HEX` in
`constants.py` pin this as a Python constant so tests can assert against
it without first capturing dynamically.  If a future provisioning step
extends a PCR — or you switch to a different selection or hash bank —
those constants become stale and the tests in
`tests/test_simulator_baseline.py` will fail loudly.

## Caveats

* **Real TPM portability.**  These constants are simulator-specific.  On
  real hardware, BIOS/UEFI extends PCRs 0–7 with firmware measurements,
  so `pcrDigest != SIMULATOR_ZERO_PCR_DIGEST` and platform-specific
  baselining is required (see `provision.sh`'s dynamic capture).
* **One stack at a time.**  `SimulatorStack` defaults to the project name
  derived from the compose-file directory.  Pass `project_name=` if you
  need parallel stacks in CI.
* **Slow.**  `docker compose up` on a clean machine takes several seconds
  per call.  Reuse a single stack across multiple tests with a
  module- or session-scoped pytest fixture.
