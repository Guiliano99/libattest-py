# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Docker Compose lifecycle wrapper for the TPM simulator stack.

The class targets the compose file shipped in
``attestation-attester/tpm-platform-attest/docker-compose.yml`` (or any
override the caller passes) and shells out to ``docker compose`` for all
operations.  The runtime dependency is the ``docker`` CLI on PATH; no
docker SDK is required.

This is intentionally thin — there is no abstraction for "simulator only"
vs "full stack"; callers list the services they want with
:meth:`SimulatorStack.up`.  For most tests two services are enough:

* ``simulator``     — the TCG mssim TPM simulator
* ``tpm-verifier``  — Veraison challenge-response API on port 8444

Add ``provisioner`` if you need persistent EK/AK/SRK handles plus the
AK CA chain on the shared ``tpm-ca`` volume.
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Iterable, Optional, Sequence

logger = logging.getLogger(__name__)


def _default_compose_file() -> Path:
    """Locate the canonical compose file by walking up from this module."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = (
            parent
            / "attestation-attester"
            / "tpm-platform-attest"
            / "docker-compose.yml"
        )
        if candidate.is_file():
            return candidate
    # Fallback: env var override.
    env = os.environ.get("LIBATTEST_SIMULATOR_COMPOSE")
    if env and Path(env).is_file():
        return Path(env)
    raise FileNotFoundError(
        "Could not locate tpm-platform-attest/docker-compose.yml. "
        "Set LIBATTEST_SIMULATOR_COMPOSE to override."
    )


class SimulatorStack:
    """Manage a docker-compose stack for the TPM simulator.

    Use as a context manager to guarantee teardown on exit::

        with SimulatorStack() as stack:
            stack.up(["simulator", "tpm-verifier"])
            stack.wait_healthy("tpm-verifier")
            # ... run tests against the stack ...
        # stack is torn down here, including its volumes

    :param compose_file:
        Path to the ``docker-compose.yml`` to drive.  Defaults to the file
        bundled in the repository.
    :param project_name:
        Optional ``-p`` project name.  Useful when running multiple stacks
        in parallel CI jobs; defaults to the parent directory name (the
        same convention ``docker compose`` uses).
    :param remove_volumes:
        When True (default), :meth:`down` passes ``-v`` so the
        ``tpm-ca`` volume is dropped on teardown.  Set False to inspect
        the volume after a failure.
    """

    def __init__(
        self,
        compose_file: Optional[os.PathLike] = None,
        project_name: Optional[str] = None,
        remove_volumes: bool = True,
    ):
        if shutil.which("docker") is None:
            raise RuntimeError(
                "docker CLI not found on PATH; SimulatorStack requires Docker."
            )
        self.compose_file = (
            Path(compose_file) if compose_file else _default_compose_file()
        )
        self.project_name = project_name
        self.remove_volumes = remove_volumes
        self._brought_up = False

    # ── Context manager protocol ─────────────────────────────────────────────

    def __enter__(self) -> "SimulatorStack":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.down()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def up(
        self,
        services: Optional[Sequence[str]] = None,
        build: bool = False,
        timeout: int = 120,
    ) -> None:
        """Start the named services in detached mode.

        :param services:
            List of service names to start.  ``None`` brings up every service
            in the compose file (rarely what you want for tests — prefer
            naming exactly the services you need).
        :param build:
            When True, pass ``--build`` so images are rebuilt before start.
        :param timeout:
            Hard wall-clock cap on the ``docker compose up`` invocation.
        """
        cmd = self._compose_cmd("up", "-d")
        if build:
            cmd.append("--build")
        if services:
            cmd.extend(services)
        logger.info("SimulatorStack.up: %s", " ".join(cmd))
        subprocess.run(cmd, check=True, timeout=timeout)
        self._brought_up = True

    def down(self, timeout: int = 60) -> None:
        """Tear down the stack.

        Idempotent: safe to call when nothing was brought up.  Honors
        :attr:`remove_volumes` to decide whether to drop the ``tpm-ca``
        volume.
        """
        if not self._brought_up:
            return
        cmd = self._compose_cmd("down", "--remove-orphans")
        if self.remove_volumes:
            cmd.append("-v")
        logger.info("SimulatorStack.down: %s", " ".join(cmd))
        subprocess.run(cmd, check=False, timeout=timeout)
        self._brought_up = False

    # ── Service introspection ────────────────────────────────────────────────

    def health(self, service: str) -> str:
        """Return the docker health-check status of a service.

        Possible values: ``"starting"``, ``"healthy"``, ``"unhealthy"``,
        ``"none"`` (no healthcheck configured), ``"unknown"`` (container
        not yet created).
        """
        try:
            container_id = subprocess.check_output(
                self._compose_cmd("ps", "-q", service),
                text=True,
                timeout=10,
            ).strip()
        except subprocess.CalledProcessError:
            return "unknown"
        if not container_id:
            return "unknown"
        try:
            out = subprocess.check_output(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container_id],
                text=True,
                timeout=10,
                stderr=subprocess.DEVNULL,
            ).strip()
        except subprocess.CalledProcessError:
            return "unknown"
        return out or "none"

    def wait_healthy(
        self,
        service: str,
        timeout: int = 60,
        poll_interval: float = 2.0,
    ) -> None:
        """Block until the service reports ``healthy``.

        :raises TimeoutError: if the deadline is reached before the service
            transitions to ``healthy``.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = self.health(service)
            if status == "healthy":
                return
            if status == "unhealthy":
                raise RuntimeError(f"Service {service!r} reported unhealthy")
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Service {service!r} did not become healthy within {timeout}s "
            f"(last status: {self.health(service)!r})"
        )

    def wait_exited(
        self,
        service: str,
        timeout: int = 60,
        poll_interval: float = 2.0,
    ) -> int:
        """Block until ``service`` exits and return its exit code.

        Use for one-shot services like ``provisioner``.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = subprocess.check_output(
                self._compose_cmd("ps", "-a", "--format", "{{.Service}} {{.State}} {{.ExitCode}}"),
                text=True,
                timeout=10,
            )
            for row in line.splitlines():
                parts = row.strip().split()
                if len(parts) >= 3 and parts[0] == service and parts[1] == "exited":
                    return int(parts[2])
            time.sleep(poll_interval)
        raise TimeoutError(f"Service {service!r} did not exit within {timeout}s")

    # ── docker exec / logs ──────────────────────────────────────────────────

    def exec(
        self,
        service: str,
        command: str | Sequence[str],
        *,
        check: bool = True,
        timeout: int = 60,
        input_bytes: Optional[bytes] = None,
    ) -> subprocess.CompletedProcess:
        """Run a command inside ``service`` via ``docker compose exec -T``.

        Requires ``service`` to already have a long-running container.
        For one-shot services like ``provisioner`` (which exit after their
        entrypoint runs), use :meth:`run_oneshot` instead.

        :param command:
            Either a single shell string (run via ``sh -c``) or a list of
            argv tokens (run directly).
        :param input_bytes:
            Optional stdin to feed to the command.
        """
        cmd = self._compose_cmd("exec", "-T", service)
        if isinstance(command, str):
            cmd.extend(["sh", "-c", command])
        else:
            cmd.extend(command)
        return subprocess.run(
            cmd,
            check=check,
            timeout=timeout,
            input=input_bytes,
            capture_output=True,
        )

    def run_oneshot(
        self,
        service: str,
        command: str | Sequence[str],
        *,
        check: bool = True,
        timeout: int = 120,
        input_bytes: Optional[bytes] = None,
        no_deps: bool = True,
    ) -> subprocess.CompletedProcess:
        """Spin up a one-shot container based on ``service`` and run ``command``.

        Wraps ``docker compose run --rm [--no-deps] --entrypoint sh service -c "<cmd>"``.
        Useful when the service's normal entrypoint has already run and
        exited (e.g. ``provisioner``) but you still want the same image
        with all its tools (tpm2-tools, openssl, ...) bound to the same
        network and shared volume.

        :param service: Name of the service (image) to base the container on.
        :param command: Shell string or argv list to execute.
        :param no_deps: When True (default) skip starting the service's
                       compose dependencies — assume they are already up.
        """
        cmd = self._compose_cmd("run", "--rm", "-T")
        if no_deps:
            cmd.append("--no-deps")
        cmd.extend(["--entrypoint", "sh", service])
        if isinstance(command, str):
            cmd.extend(["-c", command])
        else:
            # Wrap argv in an inline sh command to keep the call signature uniform.
            cmd.extend(["-c", " ".join(shlex.quote(part) for part in command)])
        return subprocess.run(
            cmd,
            check=check,
            timeout=timeout,
            input=input_bytes,
            capture_output=True,
        )

    def logs(self, service: Optional[str] = None) -> str:
        """Return the captured logs of a service (or the whole stack)."""
        cmd = self._compose_cmd("logs", "--no-color")
        if service:
            cmd.append(service)
        return subprocess.check_output(cmd, text=True, timeout=30)

    # ── Internals ───────────────────────────────────────────────────────────

    def _compose_cmd(self, *args: str) -> list[str]:
        """Build a ``docker compose -f <file> [-p <project>] <args...>`` argv."""
        cmd = ["docker", "compose", "-f", str(self.compose_file)]
        if self.project_name:
            cmd.extend(["-p", self.project_name])
        cmd.extend(args)
        return cmd
