# SPDX-FileCopyrightText: Copyright 2026
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP client and provider dispatcher for attestation services.

Covers the two public REST APIs:

  Verification (challenge-response):
    GET    /.well-known/verification
    POST   /challenge-response/v1/newSession
    POST   /challenge-response/v1/session/{id}
    GET    /challenge-response/v1/session/{id}
    DELETE /challenge-response/v1/session/{id}

  Provisioning (endorsement):
    POST   /endorsement-provisioning/v1/submit
    GET    /endorsement-provisioning/v1/session/{id}
    DELETE /endorsement-provisioning/v1/session/{id}

Each Veraison service runs on its own TCP port.  The defaults follow the
standard Veraison deployment (verification: 8080, provisioning: 8888).

References
----------
https://github.com/veraison/docs/tree/main/api/challenge-response
https://github.com/veraison/docs/tree/main/api/endorsement-provisioning

"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import requests

from libattest.formats.csrattest import NonceResponse
from libattest.types import AttestResult
from libattest.verifier.endpoints import (
    CORIM_MEDIA_TYPE,
    PROVISIONING_MEDIA_TYPE,
    SESSION_MEDIA_TYPE,
    VerifierEndpointConfig,
)


@dataclass
class VerifiedAttestResult:  # pylint: disable=too-many-instance-attributes
    """Appraisal output produced by a verifier for one evidence item.

    This dataclass is intentionally transport-neutral.  The CMP exchange layer
    can serialize or embed the payload according to its own message handling.
    """

    oid: str
    verified: bool
    media_type: str
    payload: bytes | str | dict[str, object] | None = None
    nonce: bytes | None = None
    verifier_hint: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def payload_bytes(self) -> bytes:
        """Return the verifier result payload in a byte form."""
        if self.payload is None:
            return b""
        if isinstance(self.payload, bytes):
            return self.payload
        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")


@dataclass
class CmpAttestationFlowResult:
    """Transport-neutral result of consuming one CMP freshness nonce."""

    oid: str
    nonce: bytes
    evidence: AttestResult
    expiry: int | None = None
    verifier_hint: str | None = None
    verified_results: list[VerifiedAttestResult] = field(default_factory=list)


class AttesterProvider(ABC):  # pylint: disable=too-few-public-methods
    """Abstract evidence generator used by :class:`AttestClient`."""

    @abstractmethod
    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Generate attestation evidence for an optional freshness nonce.

        Parameters
        ----------
        nonce:
            Freshness challenge supplied by a verifier.  Providers that do
            not need a nonce may ignore this value.

        Returns
        -------
        AttestResult
            Evidence bytes or JWT plus the OID and media type needed for
            routing.

        """


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class AttestClientConfig:
    """Connection parameters for the Veraison attestation services.

    Each logical service runs on its own port.  The defaults match the
    standard Veraison deployment.

    Attributes
    ----------
    host:
        Hostname or IP address of the Veraison deployment.
    verification_port:
        TCP port for the challenge-response verification service.
    provisioning_port:
        TCP port for the endorsement provisioning service.
    scheme:
        URL scheme — ``"http"`` or ``"https"``.
    timeout:
        Request timeout in seconds applied to every call.
    tls_verify:
        Whether to verify TLS certificates.  Pass a file path to use a
        custom CA bundle instead of the system trust store.

    """

    host: str = "127.0.0.1"
    verification_port: int = 8080
    provisioning_port: int = 8888
    scheme: str = "http"
    timeout: float = 30.0
    tls_verify: bool | str = True

    @classmethod
    def localhost(
        cls,
        port: int | None = None,
        *,
        provisioning_port: int = 8888,
        scheme: str = "http",
        timeout: float = 30.0,
        tls_verify: bool | str = True,
    ) -> "AttestClientConfig":
        """Return client settings for a verifier on localhost."""
        endpoints = VerifierEndpointConfig.localhost(
            port=port,
            provisioning_port=provisioning_port,
            scheme=scheme,
        )
        return cls(
            host=endpoints.host,
            verification_port=endpoints.verification_port,
            provisioning_port=endpoints.provisioning_port,
            scheme=endpoints.scheme,
            timeout=timeout,
            tls_verify=tls_verify,
        )

    @property
    def endpoints(self) -> VerifierEndpointConfig:
        """Return the shared endpoint configuration for this client."""
        return VerifierEndpointConfig(
            host=self.host,
            verification_port=self.verification_port,
            provisioning_port=self.provisioning_port,
            scheme=self.scheme,
        )


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_MT_SESSION = SESSION_MEDIA_TYPE
_MT_PROVISIONING = PROVISIONING_MEDIA_TYPE
_MT_CORIM = CORIM_MEDIA_TYPE


class AttestClient:
    """HTTP client for the Veraison attestation services.

    The client covers the full challenge-response verification workflow
    and the endorsement-provisioning workflow.  It can also register
    :class:`AttesterProvider` instances and dispatch generated evidence to
    the correct Veraison endpoint.

    The underlying ``requests.Session`` is reused across calls.  Use the
    client as a context manager (or call :meth:`close`) to release it.

    Parameters
    ----------
    config:
        Optional :class:`AttestClientConfig` instance.  Defaults are used when
        ``None``.
    port:
        Override for the verification service port.  Takes precedence over
        ``config.verification_port`` when provided.
    providers:
        Optional map from evidence OID to evidence provider.

    Examples
    --------
    ::

        from attest_client import AttestClient, AttestClientConfig

        cfg = AttestClientConfig(host="veraison.example.com", scheme="https")
        with AttestClient(cfg) as client:
            session = client.new_session(nonce_size=32)
            session_id = session["nonce"]  # extract from response
            result = client.submit_evidence(
                session_id,
                token_bytes,
                "application/psa-attestation-token",
            )

    | ${client}= | AttestClient | config=${cfg} |
    | ${session}= | Call Method | ${client} | new_session |

    """

    def __init__(
        self,
        config: AttestClientConfig | None = None,
        port: int | None = None,
        providers: dict[str, AttesterProvider] | None = None,
    ) -> None:
        """Initialise the client with connection settings and providers."""
        self._cfg = config or AttestClientConfig()
        if port is not None:
            self._cfg.verification_port = port
        self._providers = dict(providers or {})
        self._session = requests.Session()
        self._session.verify = self._cfg.tls_verify
        self.endpoints = self._cfg.endpoints

    # -----------------------------------------------------------------------
    # Provider dispatch
    # -----------------------------------------------------------------------

    @property
    def providers(self) -> dict[str, AttesterProvider]:
        """Return registered attester providers keyed by evidence OID."""
        return dict(self._providers)

    def register_provider(self, oid: str, provider: AttesterProvider) -> None:
        """Register an attester provider for an evidence OID.

        Parameters
        ----------
        oid:
            Evidence format OID handled by the provider.
        provider:
            Provider that can generate evidence for ``oid``.

        """
        self._providers[oid] = provider

    def generate_evidence(self, oid: str, nonce: bytes | None = None) -> AttestResult:
        """Generate evidence by dispatching to the provider for ``oid``.

        Parameters
        ----------
        oid:
            Evidence format OID to generate.
        nonce:
            Optional freshness challenge for the provider.

        Returns
        -------
        AttestResult
            Generated evidence and media metadata.

        Raises
        ------
        KeyError
            If no provider is registered for ``oid``.
        ValueError
            If the provider returns evidence for a different OID.

        """
        try:
            provider = self._providers[oid]
        except KeyError as exc:
            raise KeyError(f"No attester provider registered for OID {oid!r}") from exc

        result = provider.generate_evidence(nonce)
        if result.oid != oid:
            raise ValueError(f"Provider for OID {oid!r} returned evidence for {result.oid!r}")
        return result

    def generate_all_evidence(self, nonce: bytes | None = None) -> list[AttestResult]:
        """Generate evidence from every registered provider."""
        return [self.generate_evidence(oid, nonce) for oid in self._providers]

    def distribute_attest_result(
        self,
        result: AttestResult,
        session_id: str | None = None,
    ) -> dict[str, object]:
        """Submit an attestation result to the matching Veraison endpoint.

        CoRIM payloads are sent to endorsement provisioning.  All other
        payloads are submitted as challenge-response evidence and therefore
        require ``session_id``.

        Parameters
        ----------
        result:
            Generated attestation evidence.
        session_id:
            Verification session identifier for evidence submission.

        Returns
        -------
        dict[str, object]
            Parsed JSON response from the selected endpoint.

        Raises
        ------
        ValueError
            If ``session_id`` is missing for challenge-response evidence.
        requests.HTTPError
            On any non-2xx response.

        """
        if result.media_type == _MT_CORIM:
            return self.submit_corim(result.evidence_bytes())

        if session_id is None:
            raise ValueError("session_id is required when distributing challenge-response evidence")
        return self.submit_evidence(session_id, result.evidence_bytes(), result.media_type)

    def distribute_provider_evidence(
        self,
        oid: str,
        nonce: bytes | None = None,
        session_id: str | None = None,
    ) -> dict[str, object]:
        """Generate provider evidence and submit it to the matching endpoint."""
        result = self.generate_evidence(oid, nonce)
        return self.distribute_attest_result(result, session_id)

    def distribute_all_provider_evidence(
        self,
        nonce: bytes | None = None,
        session_id: str | None = None,
    ) -> dict[str, dict[str, object]]:
        """Generate and submit evidence from every registered provider."""
        responses = {}
        for oid in self._providers:
            responses[oid] = self.distribute_provider_evidence(oid, nonce, session_id)
        return responses

    def generate_evidence_from_cmp_nonce_response(
        self,
        nonce_response: NonceResponse,
        oid: str | None = None,
    ) -> AttestResult:
        """Generate evidence using a nonce received through CMP.

        Parameters
        ----------
        nonce_response:
            Decoded CMP attestation freshness `NonceResponse`.
        oid:
            Optional evidence OID override.  Required when the CMP response
            does not carry a `type` field and more than one provider is
            registered.

        Returns
        -------
        AttestResult
            Provider evidence generated with the CMP nonce.

        Raises
        ------
        ValueError
            If no OID can be inferred, or the response carries an empty nonce.
        KeyError
            If no provider is registered for the selected OID.

        """
        nonce = bytes(nonce_response["nonce"])
        if not nonce:
            raise ValueError("CMP NonceResponse contains an empty nonce")

        selected_oid = oid
        if selected_oid is None and nonce_response["type"].isValue:
            selected_oid = str(nonce_response["type"])
        if selected_oid is None and len(self._providers) == 1:
            selected_oid = next(iter(self._providers))
        if selected_oid is None:
            raise ValueError("oid is required when CMP NonceResponse has no type field")

        return self.generate_evidence(selected_oid, nonce)

    def generate_cmp_attestation_flow_result(
        self,
        nonce_response: NonceResponse,
        oid: str | None = None,
        verified_results: list[VerifiedAttestResult] | None = None,
    ) -> CmpAttestationFlowResult:
        """Generate evidence and package CMP nonce metadata for the caller.

        CMP message construction and transmission remain outside this class.
        This method consumes one decoded `NonceResponse`, generates provider
        evidence with its nonce, and returns a transport-neutral object that
        the CMP layer can embed in its certification request flow.
        """
        evidence = self.generate_evidence_from_cmp_nonce_response(nonce_response, oid)
        expiry = int(nonce_response["expiry"]) if nonce_response["expiry"].isValue else None
        verifier_hint = str(nonce_response["hint"]) if nonce_response["hint"].isValue else None

        return CmpAttestationFlowResult(
            oid=evidence.oid,
            nonce=bytes(nonce_response["nonce"]),
            evidence=evidence,
            expiry=expiry,
            verifier_hint=verifier_hint,
            verified_results=list(verified_results or []),
        )

    # -----------------------------------------------------------------------
    # Discovery
    # -----------------------------------------------------------------------

    def get_verification_info(self) -> dict[str, object]:
        """GET /.well-known/verification

        Return the service discovery document: supported media types,
        public key, API version, service state, and active endpoints.

        Returns
        -------
        dict
            Parsed JSON discovery document.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${info}= | Call Method | ${client} | get_verification_info |

        """
        resp = self._session.get(
            self.endpoints.well_known_url(),
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # -----------------------------------------------------------------------
    # Verification — challenge-response workflow
    # -----------------------------------------------------------------------

    def new_session(self, nonce_size: int = 32) -> dict[str, object]:
        """POST /challenge-response/v1/newSession

        Create a new challenge-response session.  Returns the session
        document containing the nonce that the attester must cover.

        Parameters
        ----------
        nonce_size:
            Desired nonce length in bytes (default 32).

        Returns
        -------
        dict
            Session document with ``nonce``, ``expiry``, ``accept``,
            and ``state`` fields.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${session}= | Call Method | ${client} | new_session | 32 |

        """
        resp = self._session.post(
            self.endpoints.new_session_url(),
            params={"nonceSize": nonce_size},
            headers={"Accept": _MT_SESSION},
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def submit_evidence(
        self,
        session_id: str,
        evidence: bytes,
        media_type: str,
    ) -> dict[str, object]:
        """POST /challenge-response/v1/session/{id}

        Submit attestation evidence for an existing session.  The service
        may respond synchronously (200) or asynchronously (202).

        Parameters
        ----------
        session_id:
            Session identifier returned by :meth:`new_session`.
        evidence:
            Raw attestation token bytes.
        media_type:
            Content-Type of the evidence payload, e.g.
            ``"application/psa-attestation-token"``.

        Returns
        -------
        dict
            Updated session document (state may be ``"processing"`` or
            ``"complete"`` depending on the server mode).

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${result}= | Call Method | ${client} | submit_evidence |
        | ... | ${id} | ${token_bytes} | application/psa-attestation-token |

        """
        resp = self._session.post(
            self.endpoints.session_url(session_id),
            data=evidence,
            headers={"Content-Type": media_type, "Accept": _MT_SESSION},
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_session(self, session_id: str) -> dict[str, object]:
        """GET /challenge-response/v1/session/{id}

        Poll an existing verification session for the appraisal result.

        Parameters
        ----------
        session_id:
            Session identifier returned by :meth:`new_session`.

        Returns
        -------
        dict
            Session document; inspect ``state`` to determine whether the
            result is ready.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${session}= | Call Method | ${client} | get_session | ${id} |

        """
        resp = self._session.get(
            self.endpoints.session_url(session_id),
            headers={"Accept": _MT_SESSION},
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_session(self, session_id: str) -> None:
        """DELETE /challenge-response/v1/session/{id}

        Dispose of a verification session before it expires.

        Parameters
        ----------
        session_id:
            Session identifier returned by :meth:`new_session`.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | Call Method | ${client} | delete_session | ${id} |

        """
        resp = self._session.delete(
            self.endpoints.session_url(session_id),
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()

    # -----------------------------------------------------------------------
    # Provisioning — endorsement workflow
    # -----------------------------------------------------------------------

    def submit_corim(self, corim: bytes) -> dict[str, object]:
        """POST /endorsement-provisioning/v1/submit

        Upload a CoRIM (Concise Reference Integrity Manifest) to provision
        reference values and trust anchors into the Veraison store.

        Parameters
        ----------
        corim:
            CBOR-encoded CoRIM payload.

        Returns
        -------
        dict
            Provisioning session document with ``status`` (``"success"``,
            ``"failed"``, or ``"processing"``), optional ``failure-reason``,
            and ``expiry``.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${prov}= | Call Method | ${client} | submit_corim | ${corim_bytes} |

        """
        resp = self._session.post(
            self.endpoints.provisioning_submit_url(),
            data=corim,
            headers={"Content-Type": _MT_CORIM, "Accept": _MT_PROVISIONING},
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_provisioning_session(self, session_id: str) -> dict[str, object]:
        """GET /endorsement-provisioning/v1/session/{id}

        Poll a provisioning session for the processing status.

        Parameters
        ----------
        session_id:
            Session identifier returned by :meth:`submit_corim`.

        Returns
        -------
        dict
            Provisioning session document.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | ${prov}= | Call Method | ${client} | get_provisioning_session | ${id} |

        """
        resp = self._session.get(
            self.endpoints.provisioning_session_url(session_id),
            headers={"Accept": _MT_PROVISIONING},
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_provisioning_session(self, session_id: str) -> None:
        """DELETE /endorsement-provisioning/v1/session/{id}

        Dispose of a provisioning session before it expires.

        Parameters
        ----------
        session_id:
            Session identifier returned by :meth:`submit_corim`.

        Raises
        ------
        requests.HTTPError
            On any non-2xx response.

        Examples
        --------
        | Call Method | ${client} | delete_provisioning_session | ${id} |

        """
        resp = self._session.delete(
            self.endpoints.provisioning_session_url(session_id),
            timeout=self._cfg.timeout,
        )
        resp.raise_for_status()

    # -----------------------------------------------------------------------
    # Context manager
    # -----------------------------------------------------------------------

    def __enter__(self) -> AttestClient:
        """Enter the client context manager."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the underlying HTTP session when leaving a context."""
        self._session.close()

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()
