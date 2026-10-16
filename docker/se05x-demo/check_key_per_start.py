# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Check the simulator's start-up wiring of the attestation key (run on the host by ``make se05x-test``).

Starts ``libattest-se05xsim:local`` four times, each on a free ``127.0.0.1`` port, and
reads the attestation public key ``0xF0000012`` with :class:`Se05xClient`:

- two starts without ``SE050_SIM_ATTEST_SEED``, as compose runs the simulator, must expose
  different keys (random per start);
- two starts with the same seed must expose the same key (deterministic, tests only).

Exits 0 when both hold. Every container is removed, whatever happens.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from libattest.attester.se05x_client import Se05xClient
from libattest.formats.se05x.apdu import ATTEST_KEY_ID

IMAGE = "libattest-se05xsim:local"
_START_TIMEOUT = 20.0  # seconds; the server waits for a whole second before it listens


def _docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def attestation_key(name: str, seed: str | None) -> bytes:
    """Start one simulator as container *name*, return its ``0xF0000012`` point, remove it."""
    env = ["-e", f"SE050_SIM_ATTEST_SEED={seed}"] if seed else []
    container = _docker("run", "-d", "--rm", "--init", "--name", name, "-p", "127.0.0.1::8050", *env, IMAGE)
    try:
        port = int(_docker("port", container, "8050/tcp").splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + _START_TIMEOUT
        while True:
            try:
                with Se05xClient("127.0.0.1", port) as se:
                    se.select()
                    return se.read_object(ATTEST_KEY_ID)
            except OSError:  # the port proxy accepts before the server listens
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.3)
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)


def main() -> int:
    """Run the four starts; return the process exit code."""
    prefix = f"{os.environ.get('COMPOSE_PROJECT_NAME', 'se05x-demo')}-keycheck-{os.getpid()}"
    random_1, random_2 = (attestation_key(f"{prefix}-random-{n}", None) for n in (1, 2))
    seeded_1, seeded_2 = (attestation_key(f"{prefix}-seeded-{n}", "libattest-keycheck") for n in (1, 2))
    checks = {
        "two unseeded starts expose different attestation keys": random_1 != random_2,
        "two starts with the same seed expose the same attestation key": seeded_1 == seeded_2,
    }
    for label, point in [
        ("unseeded 1", random_1),
        ("unseeded 2", random_2),
        ("seeded 1", seeded_1),
        ("seeded 2", seeded_2),
    ]:
        print(f"  {label:10}  0x{ATTEST_KEY_ID:08X} = {point.hex()[:32]}...")
    for check, ok in checks.items():
        print(f"{'PASS' if ok else 'FAIL'}: {check}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
