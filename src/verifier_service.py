# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""Abstract FastAPI service base for Veraison-compatible attestation endpoints.

Subclass :class:`VeraisonServiceBase`, implement the abstract methods, then
call :meth:`~VeraisonServiceBase.run` to start the service — or access
:attr:`~VeraisonServiceBase.app` for ASGI embedding.

The URL layout mirrors the official Veraison REST APIs:

  Verification (challenge-response):
    GET    /.well-known/verification
    POST   /challenge-response/v1/newSession
    POST   /challenge-response/v1/session/{session_id}
    GET    /challenge-response/v1/session/{session_id}
    DELETE /challenge-response/v1/session/{session_id}

  Provisioning (endorsement):
    POST   /endorsement-provisioning/v1/submit
    GET    /endorsement-provisioning/v1/session/{session_id}
    DELETE /endorsement-provisioning/v1/session/{session_id}

References
----------
https://github.com/veraison/docs/tree/main/api/challenge-response
https://github.com/veraison/docs/tree/main/api/endorsement-provisioning

"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.responses import Response

from libattest.verifier.endpoints import (
    DEFAULT_VERIFICATION_PORT,
    PROVISIONING_BASE_PATH,
    PROVISIONING_MEDIA_TYPE,
    SESSION_MEDIA_TYPE,
    VERIFICATION_BASE_PATH,
    WELL_KNOWN_VERIFICATION_PATH,
)

# ---------------------------------------------------------------------------
# Media types
# ---------------------------------------------------------------------------

_MT_SESSION = SESSION_MEDIA_TYPE
_MT_PROVISIONING = PROVISIONING_MEDIA_TYPE

# ---------------------------------------------------------------------------
# Route prefixes
# ---------------------------------------------------------------------------

_WELL_KNOWN = WELL_KNOWN_VERIFICATION_PATH
_VERIFICATION_BASE = VERIFICATION_BASE_PATH
_PROVISIONING_BASE = PROVISIONING_BASE_PATH


# ---------------------------------------------------------------------------
# Optional configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceConfig:
    """Optional server configuration beyond the port.

    Attributes
    ----------
    host:
        Bind address.  Defaults to ``"0.0.0.0"`` so the service is
        reachable inside Docker.  Use ``"127.0.0.1"`` to restrict to
        loopback.
    log_level:
        Uvicorn log level (``"debug"``, ``"info"``, ``"warning"``,
        ``"error"``, ``"critical"``).

    """

    host: str = "0.0.0.0"
    log_level: str = "info"


# ---------------------------------------------------------------------------
# Abstract service base
# ---------------------------------------------------------------------------


class VeraisonServiceBase(ABC):
    """Abstract base for a Veraison-compatible attestation service.

    Subclass this class and implement every abstract method with real
    attestation logic.  The constructor registers all Veraison API routes
    on the embedded FastAPI application; no subclass needs to touch routing.

    Parameters
    ----------
    port:
        TCP port the service will listen on (default 8080).
    config:
        Optional :class:`ServiceConfig` for bind address and log level.
        Defaults are used when ``None``.

    Examples
    --------
    ::

        class MyVeraisonService(VeraisonServiceBase):
            def get_verification_info(self) -> dict:
                return {"version": "1.0", "status": "active"}

            def new_session(self, nonce_size: int) -> dict:
                return {"nonce": os.urandom(nonce_size).hex(), "state": "waiting"}

            # ... implement remaining abstract methods ...


        MyVeraisonService(port=9090).run()

    """

    def __init__(
        self,
        port: int = DEFAULT_VERIFICATION_PORT,
        config: ServiceConfig | None = None,
    ) -> None:
        """Register all Veraison API routes on the embedded FastAPI app."""
        self.port = port
        self._config = config or ServiceConfig()
        self._app = self._register_routes(FastAPI(title="Veraison Attestation Service", version="1.0"))

    # -----------------------------------------------------------------------
    # Route registration
    # -----------------------------------------------------------------------

    def _json_response(self, payload: object, media_type: str, status_code: int = 200) -> Response:
        return Response(content=json.dumps(payload), media_type=media_type, status_code=status_code)

    def _register_routes(self, app: FastAPI) -> FastAPI:

        # -- Discovery -------------------------------------------------------

        @app.get(_WELL_KNOWN)
        async def _well_known() -> Response:
            return self._json_response(
                self.get_verification_info(),
                media_type="application/json",
            )

        # -- Challenge-response: new session ----------------------------------

        @app.post(_VERIFICATION_BASE + "/newSession", status_code=201)
        async def _new_session(
            nonceSize: int = Query(default=32, alias="nonceSize"),
        ) -> Response:
            return self._json_response(
                self.new_session(nonceSize),
                media_type=_MT_SESSION,
                status_code=201,
            )

        # -- Challenge-response: submit evidence ------------------------------

        @app.post(_VERIFICATION_BASE + "/session/{session_id}")
        async def _submit_evidence(session_id: str, request: Request) -> Response:
            body = await request.body()
            media_type = request.headers.get("content-type", "")
            return self._json_response(
                self.submit_evidence(session_id, body, media_type),
                media_type=_MT_SESSION,
            )

        # -- Challenge-response: poll session ---------------------------------

        @app.get(_VERIFICATION_BASE + "/session/{session_id}")
        async def _get_session(session_id: str) -> Response:
            return self._json_response(
                self.get_session(session_id),
                media_type=_MT_SESSION,
            )

        # -- Challenge-response: delete session -------------------------------

        @app.delete(_VERIFICATION_BASE + "/session/{session_id}", status_code=204)
        async def _delete_session(session_id: str) -> Response:
            self.delete_session(session_id)
            return Response(status_code=204)

        # -- Provisioning: submit CoRIM ---------------------------------------

        @app.post(_PROVISIONING_BASE + "/submit")
        async def _submit_corim(request: Request) -> Response:
            body = await request.body()
            return self._json_response(
                self.submit_corim(body),
                media_type=_MT_PROVISIONING,
            )

        # -- Provisioning: poll session ---------------------------------------

        @app.get(_PROVISIONING_BASE + "/session/{session_id}")
        async def _get_provisioning_session(session_id: str) -> Response:
            return self._json_response(
                self.get_provisioning_session(session_id),
                media_type=_MT_PROVISIONING,
            )

        # -- Provisioning: delete session -------------------------------------

        @app.delete(_PROVISIONING_BASE + "/session/{session_id}", status_code=204)
        async def _delete_provisioning_session(session_id: str) -> Response:
            self.delete_provisioning_session(session_id)
            return Response(status_code=204)

        return app

    # -----------------------------------------------------------------------
    # Abstract methods — implement these in subclasses
    # -----------------------------------------------------------------------

    @abstractmethod
    def get_verification_info(self) -> dict:
        """Return the /.well-known/verification discovery document.

        The response should include supported media types, the service
        public key, API version, service state, and active endpoints.

        Returns
        -------
        dict
            JSON-serialisable discovery document.

        """

    @abstractmethod
    def new_session(self, nonce_size: int) -> dict:
        """Create a new challenge-response session.

        Parameters
        ----------
        nonce_size:
            Requested nonce length in bytes.

        Returns
        -------
        dict
            Session document with at least ``nonce``, ``expiry``,
            ``accept``, and ``state`` fields.

        """

    @abstractmethod
    def submit_evidence(
        self,
        session_id: str,
        evidence: bytes,
        media_type: str,
    ) -> dict:
        """Process attestation evidence for an existing session.

        Parameters
        ----------
        session_id:
            Session identifier from :meth:`new_session`.
        evidence:
            Raw attestation token bytes.
        media_type:
            Content-Type of *evidence* (e.g.
            ``"application/psa-attestation-token"``).

        Returns
        -------
        dict
            Updated session document.  Set ``state`` to ``"complete"``
            when the result is ready.

        """

    @abstractmethod
    def get_session(self, session_id: str) -> dict:
        """Return the current state of a verification session.

        Parameters
        ----------
        session_id:
            Session identifier from :meth:`new_session`.

        Returns
        -------
        dict
            Session document.

        Raises
        ------
        fastapi.HTTPException
            404 if *session_id* is unknown; 410 if expired.

        """

    @abstractmethod
    def delete_session(self, session_id: str) -> None:
        """Discard a verification session before it expires.

        Parameters
        ----------
        session_id:
            Session identifier from :meth:`new_session`.

        Raises
        ------
        fastapi.HTTPException
            404 if *session_id* is unknown.

        """

    @abstractmethod
    def submit_corim(self, corim: bytes) -> dict:
        """Provision reference values and trust anchors from a CoRIM.

        Parameters
        ----------
        corim:
            CBOR-encoded CoRIM payload (Content-Type ``application/rim+cbor``).

        Returns
        -------
        dict
            Provisioning session document with ``status``, optional
            ``failure-reason``, and ``expiry``.

        """

    @abstractmethod
    def get_provisioning_session(self, session_id: str) -> dict:
        """Return the current state of a provisioning session.

        Parameters
        ----------
        session_id:
            Session identifier from :meth:`submit_corim`.

        Returns
        -------
        dict
            Provisioning session document.

        Raises
        ------
        fastapi.HTTPException
            404 if *session_id* is unknown.

        """

    @abstractmethod
    def delete_provisioning_session(self, session_id: str) -> None:
        """Discard a provisioning session before it expires.

        Parameters
        ----------
        session_id:
            Session identifier from :meth:`submit_corim`.

        Raises
        ------
        fastapi.HTTPException
            404 if *session_id* is unknown.

        """

    # -----------------------------------------------------------------------
    # Runner
    # -----------------------------------------------------------------------

    @property
    def app(self) -> FastAPI:
        """The FastAPI application — use for ASGI embedding or testing."""
        return self._app

    def run(self) -> None:
        """Start the service with uvicorn on :attr:`port`.

        Blocks until the server is stopped (e.g. via SIGINT).
        """
        uvicorn.run(
            self._app,
            host=self._config.host,
            port=self.port,
            log_level=self._config.log_level,
        )
