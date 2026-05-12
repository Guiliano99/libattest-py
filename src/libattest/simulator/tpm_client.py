# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Drive ``tpm2-tools`` against the simulator from Python.

This client shells out to the ``provisioner`` (or any service with
``tpm2-tools`` installed and the simulator on its TCTI) inside a running
:class:`~libattest.simulator.docker_stack.SimulatorStack`.  It is a
convenience layer for tests — not a complete TSS2 binding.

Why ``docker compose exec`` instead of native bindings?  Because the
existing images already ship ``tpm2-tools`` and have the correct TCTI
configured; reusing them keeps the test surface identical to what the
end-to-end flow uses, and avoids pulling a heavy native dependency
(``tpm2-pytss``) into the test environment.
"""

from __future__ import annotations

import hashlib
import logging
import shlex
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from libattest.simulator.docker_stack import SimulatorStack

logger = logging.getLogger(__name__)


class TpmClient:
    """Run ``tpm2-tools`` commands inside a stack service.

    The client picks one of two execution paths automatically:

    * ``run_oneshot`` (default) — spins up a fresh container based on
      ``service``'s image with ``docker compose run --rm --no-deps``.  This
      works even if the service's normal entrypoint has already run and
      exited (e.g. ``provisioner``).
    * ``exec`` (when ``mode="exec"``) — joins an existing long-running
      container.  Use this when you need to share state across calls
      (e.g. PCR extends that should accumulate within a session).

    :param stack: A :class:`SimulatorStack` with the simulator service up.
    :param service:
        Name of the compose service whose image carries ``tpm2-tools``.
        Defaults to ``provisioner``; ``tpm-platform-attester`` also works.
    :param tcti:
        TCTI string set in the container's environment.  Defaults to the
        same value the production entrypoint uses.
    :param mode:
        Either ``"run"`` (one-shot, default) or ``"exec"`` (long-running).
    """

    def __init__(
        self,
        stack: "SimulatorStack",
        service: str = "provisioner",
        tcti: str = "mssim:host=simulator,port=2321",
        mode: str = "run",
    ):
        if mode not in ("run", "exec"):
            raise ValueError(f"mode must be 'run' or 'exec', got {mode!r}")
        self.stack = stack
        self.service = service
        self.tcti = tcti
        self.mode = mode

    # ── Internal dispatch ────────────────────────────────────────────────────

    def _run(self, command: str, *, check: bool = True, timeout: int = 60):
        """Dispatch ``command`` through the configured execution mode."""
        if self.mode == "exec":
            return self.stack.exec(self.service, command, check=check, timeout=timeout)
        return self.stack.run_oneshot(
            self.service, command, check=check, timeout=timeout
        )

    # ── tpm2_* wrappers ──────────────────────────────────────────────────────

    def startup_clear(self, retries: int = 10) -> None:
        """Issue ``TPM2_Startup(CLEAR)``.  Retries while the simulator boots."""
        cmd = (
            f"export TPM2TOOLS_TCTI={shlex.quote(self.tcti)}; "
            f"for i in $(seq 1 {retries}); do tpm2_startup -c 2>/dev/null && exit 0; sleep 1; done; "
            f"exit 1"
        )
        logger.debug("TpmClient.startup_clear")
        self._run(cmd)

    def pcr_read(
        self,
        selection: str = "sha256:0,1,2,3,4,5,6,7",
    ) -> bytes:
        """Read PCRs and return the raw concatenated bytes.

        Output equals the ``-o`` blob from ``tpm2_pcrread``: the selected
        PCRs serialised in selection order, with no length prefix.  This
        is exactly the byte string the TPM hashes to compute
        ``TPMS_QUOTE_INFO.pcrDigest``.

        In ``run`` mode each call performs ``TPM2_Startup(CLEAR)`` first
        so the simulator is in a known state; in ``exec`` mode the caller
        is responsible for startup.
        """
        startup = "tpm2_startup -c 2>/dev/null; " if self.mode == "run" else ""
        cmd = (
            f"export TPM2TOOLS_TCTI={shlex.quote(self.tcti)}; "
            f"{startup}"
            f"tpm2_pcrread {shlex.quote(selection)} -o /tmp/_libattest_pcr.bin >/dev/null && "
            f"cat /tmp/_libattest_pcr.bin"
        )
        result = self._run(cmd)
        return result.stdout

    def pcr_digest(
        self,
        selection: str = "sha256:0,1,2,3,4,5,6,7",
        hash_algorithm: str = "sha256",
    ) -> bytes:
        """Compute ``pcrDigest = H_alg(PCR0 || PCR1 || ... || PCRn)``.

        This is the value the TPM produces inside ``TPMS_QUOTE_INFO`` and
        the value :class:`PcrReferenceValues` compares against.  The
        ``hash_algorithm`` must match the bank named in ``selection``.
        """
        raw = self.pcr_read(selection)
        if hash_algorithm.lower() != "sha256":
            return hashlib.new(hash_algorithm, raw).digest()
        return hashlib.sha256(raw).digest()

    def pcr_extend(self, pcr_index: int, value_hex: str, bank: str = "sha256") -> None:
        """Extend a PCR with a digest value.

        ``value_hex`` is the digest to extend with, *not* a pre-image.
        Mainly useful for negative tests that want to drift the
        simulator's PCRs away from the deterministic reset state.
        Only meaningful in ``mode="exec"`` (the extend persists in the
        running container's TPM session) — in one-shot ``mode="run"``
        the extend disappears with the container.
        """
        cmd = (
            f"export TPM2TOOLS_TCTI={shlex.quote(self.tcti)}; "
            f"tpm2_pcrextend {pcr_index}:{bank}={shlex.quote(value_hex)}"
        )
        self._run(cmd)

    def read_persistent_handles(self) -> list[int]:
        """Return the list of currently persistent TPM handles."""
        cmd = (
            f"export TPM2TOOLS_TCTI={shlex.quote(self.tcti)}; "
            f"tpm2_getcap handles-persistent | awk '{{print $2}}'"
        )
        result = self._run(cmd)
        out: list[int] = []
        for line in result.stdout.decode().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(int(line, 16))
            except ValueError:
                continue
        return out
