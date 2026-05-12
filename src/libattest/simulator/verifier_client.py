# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP client for the ``tpm-verifier`` Veraison challenge-response API.

Wraps the three endpoints the docker-compose stack exposes:

* ``POST /challenge-response/v1/newSession?nonceSize=N`` — open a session.
* ``POST /challenge-response/v1/session/{id}`` — submit evidence.
* ``GET  /ear-verification-key`` — fetch the EAR signing public key (PEM).

The client is intentionally low-level: it does not build or parse
attestation bundles itself (use the verifier backends in
:mod:`libattest.verifier.tpm` for that).  It only handles the HTTP shape
so test code can submit raw bytes and assert on the JSON / EAR JWT that
comes back.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Inlined from libattest.verifier.endpoints to keep this subpackage importable
# without the verifier-side dependencies (pyasn1, pyasn1-alt-modules).  These
# values are part of the Veraison challenge-response API contract and only
# change when the API itself does, so duplication is cheap.
_NEW_SESSION_PATH = "/challenge-response/v1/newSession"
_SESSION_MEDIA_TYPE = "application/vnd.veraison.challenge-response-session+json"


@dataclass(frozen=True)
class NewSession:
    """Result of a successful ``newSession`` request."""

    nonce: bytes
    """Raw nonce bytes (already base64-decoded from the JSON response)."""

    session_url: str
    """Absolute URL of the session resource (resolved from the Location header)."""

    accept: tuple[str, ...]
    """Media types the verifier will accept for evidence submission."""


class VerifierClient:
    """Talk to the Veraison challenge-response API of ``tpm-verifier``.

    :param base_url:
        Where the verifier listens.  When running tests against the
        compose stack, ``http://localhost:8444`` works because the primary
        verifier publishes that port; for the secondary,
        ``http://localhost:8445``.  When running on the same docker
        network, use the service name (``http://tpm-verifier:8444``).
    :param tls_verify:
        Whether to verify TLS when ``base_url`` is HTTPS.  Defaults to
        ``False`` to mirror the demo's plain-HTTP setup.
    :param timeout:
        Per-request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8444",
        tls_verify: bool = False,
        timeout: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.tls_verify = tls_verify
        self.timeout = timeout

    # ── newSession ──────────────────────────────────────────────────────────

    def new_session(self, nonce_size: int = 32) -> NewSession:
        """Open a challenge-response session and capture the nonce + URL."""
        url = f"{self.base_url}{_NEW_SESSION_PATH}?nonceSize={nonce_size}"
        logger.debug("VerifierClient.new_session → POST %s", url)
        resp = requests.post(url, timeout=self.timeout, verify=self.tls_verify)
        resp.raise_for_status()
        data = resp.json()

        nonce_b64 = data.get("nonce", "")
        if not nonce_b64:
            raise RuntimeError("Verifier returned empty nonce in newSession")
        nonce = base64.b64decode(nonce_b64)

        location = resp.headers.get("Location", "")
        if not location:
            raise RuntimeError("Verifier did not return a Location header")
        # Server returns either an absolute URL or a path; resolve relative to base_url.
        session_url = (
            location if location.startswith("http")
            else f"{self.base_url}{location}"
        )
        accept = tuple(data.get("accept", ()))
        return NewSession(nonce=nonce, session_url=session_url, accept=accept)

    # ── submit evidence ─────────────────────────────────────────────────────

    def submit(
        self,
        session_url: str,
        body: bytes,
        content_type: str = "application/octet-stream",
    ) -> dict:
        """POST evidence ``body`` to ``session_url`` and return the JSON response.

        The verifier always responds with JSON; on success ``status`` is
        ``"complete"`` and ``result`` carries the EAR JWT.  On failure the
        verifier returns ``status="contraindicated"`` (or HTTP 4xx).  The
        caller decides what to do with the verdict.
        """
        logger.debug("VerifierClient.submit → POST %s (%d bytes)", session_url, len(body))
        resp = requests.post(
            session_url,
            data=body,
            headers={"Content-Type": content_type, "Accept": _SESSION_MEDIA_TYPE},
            timeout=self.timeout,
            verify=self.tls_verify,
        )
        resp.raise_for_status()
        return resp.json()

    # ── EAR signing key ─────────────────────────────────────────────────────

    def ear_verification_key_pem(self) -> bytes:
        """GET the EAR JWT signing public key as PEM bytes."""
        url = f"{self.base_url}/ear-verification-key"
        logger.debug("VerifierClient.ear_verification_key_pem → GET %s", url)
        resp = requests.get(url, timeout=self.timeout, verify=self.tls_verify)
        resp.raise_for_status()
        return resp.content

    def ear_verification_key(self):
        """Return the EAR JWT signing public key as a ``cryptography`` object."""
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        return load_pem_public_key(self.ear_verification_key_pem())
