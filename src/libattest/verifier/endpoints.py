# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Shared verifier endpoint defaults for clients and services."""

from dataclasses import dataclass
from urllib.parse import urlparse

from libattest.formats import media_types as _media_types

DEFAULT_VERIFIER_HOST = "127.0.0.1"
DEFAULT_VERIFICATION_PORT = 8080
DEFAULT_PROVISIONING_PORT = 8888
DEFAULT_SCHEME = "http"

WELL_KNOWN_VERIFICATION_PATH = "/.well-known/verification"
VERIFICATION_BASE_PATH = "/challenge-response/v1"
PROVISIONING_BASE_PATH = "/endorsement-provisioning/v1"

NEW_SESSION_PATH = f"{VERIFICATION_BASE_PATH}/newSession"
SESSION_PATH_TEMPLATE = f"{VERIFICATION_BASE_PATH}/session/{{session_id}}"
PROVISIONING_SUBMIT_PATH = f"{PROVISIONING_BASE_PATH}/submit"
PROVISIONING_SESSION_PATH_TEMPLATE = f"{PROVISIONING_BASE_PATH}/session/{{session_id}}"

SESSION_MEDIA_TYPE = _media_types.SESSION_MEDIA_TYPE
PROVISIONING_MEDIA_TYPE = _media_types.PROVISIONING_MEDIA_TYPE
CORIM_MEDIA_TYPE = _media_types.CORIM_MEDIA_TYPE


@dataclass(frozen=True)
class VerifierEndpointConfig:
    """Endpoint locations for a Veraison-compatible verifier deployment.

    Provides URL accessors for both the challenge-response (verification)
    and endorsement-provisioning APIs so that consumers can issue
    ``newSession`` and ``submit-evidence`` requests without hand-assembling
    URLs.
    """

    host: str = DEFAULT_VERIFIER_HOST
    verification_port: int = DEFAULT_VERIFICATION_PORT
    provisioning_port: int = DEFAULT_PROVISIONING_PORT
    scheme: str = DEFAULT_SCHEME

    @classmethod
    def localhost(
        cls,
        port: int | None = None,
        *,
        provisioning_port: int = DEFAULT_PROVISIONING_PORT,
        scheme: str = DEFAULT_SCHEME,
    ) -> "VerifierEndpointConfig":
        """Return the default localhost verifier endpoint configuration."""
        return cls(
            verification_port=port or DEFAULT_VERIFICATION_PORT,
            provisioning_port=provisioning_port,
            scheme=scheme,
        )

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        provisioning_port: int | None = None,
    ) -> "VerifierEndpointConfig":
        """Parse a base URL like ``"https://verifier.example.com:8443"`` into a config.

        Parameters
        ----------
        url:
            Absolute base URL.  Trailing path is ignored — only scheme,
            host, and port are taken from *url*.
        provisioning_port:
            Optional separate provisioning port.  Defaults to
            :data:`DEFAULT_PROVISIONING_PORT` (the verification port is
            normally distinct from the provisioning port in real
            Veraison deployments).

        Raises
        ------
        ValueError
            If *url* has no scheme or host.

        """
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"Unsupported URL scheme {parsed.scheme!r} in {url!r}")
        if not parsed.hostname:
            raise ValueError(f"URL {url!r} has no hostname")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return cls(
            host=parsed.hostname,
            verification_port=port,
            provisioning_port=provisioning_port if provisioning_port is not None else DEFAULT_PROVISIONING_PORT,
            scheme=parsed.scheme,
        )

    @property
    def base_url(self) -> str:
        """Return the verification base URL ``scheme://host:port``."""
        return f"{self.scheme}://{self.host}:{self.verification_port}"

    def verification_url(self, path: str) -> str:
        """Build an absolute URL for the verification service."""
        return f"{self.base_url}{path}"

    def provisioning_url(self, path: str) -> str:
        """Build an absolute URL for the provisioning service."""
        return f"{self.scheme}://{self.host}:{self.provisioning_port}{path}"

    def well_known_url(self) -> str:
        """Return the verification discovery URL."""
        return self.verification_url(WELL_KNOWN_VERIFICATION_PATH)

    def new_session_url(self) -> str:
        """Return the challenge-response newSession URL.

        Equivalent to ``base_url + NEW_SESSION_PATH``.
        """
        return self.verification_url(NEW_SESSION_PATH)

    def session_url(self, session_id: str) -> str:
        """Return the challenge-response session URL for *session_id*."""
        return self.verification_url(SESSION_PATH_TEMPLATE.format(session_id=session_id))

    def submit_evidence_url(self, session_id: str) -> str:
        """Return the URL to which evidence is POSTed for *session_id*.

        Alias for :meth:`session_url` — in the Veraison challenge-response
        API, evidence is submitted by ``POST``-ing to the session URL.
        """
        return self.session_url(session_id)

    def provisioning_submit_url(self) -> str:
        """Return the endorsement-provisioning submission URL."""
        return self.provisioning_url(PROVISIONING_SUBMIT_PATH)

    def provisioning_session_url(self, session_id: str) -> str:
        """Return the endorsement-provisioning session URL."""
        return self.provisioning_url(PROVISIONING_SESSION_PATH_TEMPLATE.format(session_id=session_id))
