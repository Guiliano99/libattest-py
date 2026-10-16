# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""In-memory verifier routing for MockCA-style attestation flows."""

import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Union
from urllib.parse import urlparse

from pyasn1.type import univ

from libattest.formats.csrattest import AttestationBundle, decode_attestation_bundle
from libattest.formats.media_types import base_media_type, media_type_set
from libattest.types import BundleVerifyResult, VerifyResult
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.endpoints import VerifierEndpointConfig

logger = logging.getLogger(__name__)

_DEFAULT_NONCE_TTL = 300.0  # seconds

EndpointLike = Union[VerifierEndpointConfig, str, None]


class VerifierRouteError(ValueError):
    """Raised when no allowed verifier route can be selected."""


@dataclass(frozen=True)
class VerifierRoutingPolicy:
    """Policy controlling URL hints and fallback routing."""

    allow_unregistered_verifier_urls: bool = False
    allowed_url_prefixes: tuple[str, ...] = ()

    def validate_hint(self, hint: str | None) -> None:
        """Reject direct URL hints unless policy explicitly allows them."""
        if not hint or not _is_url_hint(hint):
            return
        if not self.allow_unregistered_verifier_urls:
            raise VerifierRouteError(f"URL verifier hint is not allowed by policy: {hint}")
        if self.allowed_url_prefixes and not hint.startswith(self.allowed_url_prefixes):
            raise VerifierRouteError(f"URL verifier hint is outside the allowed prefixes: {hint}")


@dataclass
class VerifierRoute:
    """Registered verifier route.

    Attributes
    ----------
    name:
        Logical route name (used for hint matching).
    verifier:
        Concrete :class:`AttestationVerifier` implementation.
    evidence_types:
        Set of evidence-type OIDs this route handles.
    endpoint:
        Optional verifier endpoint.  Either:

        * a :class:`VerifierEndpointConfig` — the route can produce
          ``new_session_url`` and ``submit_evidence_url`` directly.
        * a base URL string (``"https://verifier.example.com:8443"``)
          — used for hint matching; URL builders parse it on demand.
        * ``None`` — the route is local-only (no remote endpoint).
    accepts:
        Media types this route's verifier will appraise.  Empty means the route
        makes no claim and any media type is allowed through to it.

    """

    name: str
    verifier: AttestationVerifier
    evidence_types: set[str] = field(default_factory=set)
    endpoint: EndpointLike = None
    accepts: frozenset[str] = frozenset()

    def matches_evidence_type(self, evidence_type: str | None) -> bool:
        """Return whether this route is registered for the evidence type."""
        return evidence_type is not None and evidence_type in self.evidence_types

    def accepts_media_type(self, media_type: str | None) -> bool:
        """Return whether this route will appraise *media_type* (parameters ignored)."""
        if media_type is None or not self.accepts:
            return True
        return base_media_type(media_type) in self.accepts

    def matches_hint(self, hint: str | None) -> bool:
        """Return whether a hint selects this route."""
        if hint is None:
            return False
        if hint == self.name:
            return True
        if isinstance(self.endpoint, str):
            return hint == self.endpoint
        if isinstance(self.endpoint, VerifierEndpointConfig):
            return hint == self.endpoint.base_url
        return False

    # ── URL helpers ────────────────────────────────────────────────────────
    #
    # Consumers (CMP handlers, attest_client) call these instead of building
    # paths by hand.  A route configured with a VerifierEndpointConfig hands
    # off URL assembly to that config; a route configured with a bare URL
    # string is parsed on demand.

    def endpoint_config(self) -> VerifierEndpointConfig:
        """Return the resolved :class:`VerifierEndpointConfig` for this route.

        Raises
        ------
        VerifierRouteError
            If the route has no endpoint configured.

        """
        if isinstance(self.endpoint, VerifierEndpointConfig):
            return self.endpoint
        if isinstance(self.endpoint, str):
            return VerifierEndpointConfig.from_url(self.endpoint)
        raise VerifierRouteError(
            f"Route {self.name!r} has no endpoint configured; set endpoint=VerifierEndpointConfig(...) or a URL string"
        )

    def new_session_url(self) -> str:
        """Return the URL to call to start a new challenge-response session."""
        return self.endpoint_config().new_session_url()

    def session_url(self, session_id: str) -> str:
        """Return the per-session URL for *session_id*."""
        return self.endpoint_config().session_url(session_id)

    def submit_evidence_url(self, session_id: str) -> str:
        """Return the URL to POST evidence to for *session_id*.

        Alias for :meth:`session_url` — in the Veraison API, evidence is
        submitted by POSTing to the session URL.
        """
        return self.endpoint_config().submit_evidence_url(session_id)

    def well_known_url(self) -> str:
        """Return the verification discovery URL."""
        return self.endpoint_config().well_known_url()

    def base_url(self) -> str:
        """Return the verification base URL (``scheme://host:port``)."""
        return self.endpoint_config().base_url


@dataclass
class _NonceEntry:
    """Nonce route mapping with an expiry timestamp."""

    route_name: str
    expires_at: float


class VerifierRouter:
    """Select verifier backends by hint, evidence type, default, or nonce.

    Parameters
    ----------
    policy:
        URL-hint policy.  Defaults are used when ``None``.
    nonce_ttl:
        Seconds before a stored nonce-to-route mapping expires.  Stale
        entries are evicted lazily on the next :meth:`get_nonce` or
        :meth:`verify_token` call.  Defaults to 300 seconds (5 minutes).

    """

    def __init__(
        self,
        policy: VerifierRoutingPolicy | None = None,
        nonce_ttl: float = _DEFAULT_NONCE_TTL,
    ) -> None:
        """Initialize with an optional routing policy and nonce TTL."""
        self.policy = policy or VerifierRoutingPolicy()
        self._nonce_ttl = nonce_ttl
        self._routes: dict[str, VerifierRoute] = {}
        self._default_route_name: str | None = None
        self._nonce_routes: dict[bytes, _NonceEntry] = {}

    @property
    def routes(self) -> dict[str, VerifierRoute]:
        """Return registered routes keyed by route name."""
        return dict(self._routes)

    def register(
        self,
        name: str,
        verifier: AttestationVerifier,
        *,
        evidence_types: list[str | univ.ObjectIdentifier] | tuple[str | univ.ObjectIdentifier, ...] = (),
        endpoint: EndpointLike = None,
        accepts: str | Iterable[str] | None = None,
        default: bool = False,
    ) -> None:
        """Register one verifier route.

        ``endpoint`` may be a :class:`VerifierEndpointConfig`, a base URL
        string, or ``None``.  When set, the resulting :class:`VerifierRoute`
        exposes ``new_session_url()`` and ``submit_evidence_url(session_id)``
        for the Veraison challenge-response scheme.

        ``accepts`` declares the media types the route will appraise — a single media
        type as a string, or several as any iterable.  It defaults to whatever *verifier*
        declares (its ``accepts`` set, else its ``media_type``), and is empty — meaning
        "no claim, allow anything" — for a verifier that declares neither.

        ``default`` must be passed explicitly to make this the fallback route.  It is
        **not** inferred from being registered first: an implicit default sends evidence
        of an unrecognised type to an arbitrary verifier, which is a fail-open dispatch.
        """
        evidence_type_set = {str(evidence_type) for evidence_type in evidence_types}
        self._routes[name] = VerifierRoute(
            name=name,
            verifier=verifier,
            evidence_types=evidence_type_set,
            endpoint=endpoint,
            accepts=media_type_set(accepts) if accepts is not None else _declared_media_types(verifier),
        )
        if default:
            self._default_route_name = name

    def _evict_expired_nonces(self) -> None:
        """Remove nonce entries whose TTL has elapsed."""
        now = time.monotonic()
        expired = [k for k, v in self._nonce_routes.items() if v.expires_at <= now]
        for k in expired:
            logger.debug("Evicting expired nonce entry for route %r", self._nonce_routes[k].route_name)
            del self._nonce_routes[k]

    def resolve(
        self,
        *,
        evidence_type: str | univ.ObjectIdentifier | None = None,
        hint: str | None = None,
        nonce: bytes | None = None,
        media_type: str | None = None,
    ) -> VerifierRoute:
        """Resolve a verifier route using nonce, hint, evidence type, then default.

        *media_type*, when the caller knows it from the wire, is a gate rather than a
        preference: nonce and hint are explicit bindings, so a route selected by one
        that does not accept the media type is an error, not a reason to look further.
        Evidence-type matching does consider it, because several routes may legitimately
        register the same OID for different renderings of it.
        """
        self._evict_expired_nonces()

        if nonce is not None:
            entry = self._nonce_routes.get(nonce)
            if entry is not None:
                return self._require_media_type(self._routes[entry.route_name], media_type)

        self.policy.validate_hint(hint)

        for route in self._routes.values():
            if route.matches_hint(hint):
                return self._require_media_type(route, media_type)

        evidence_type_text = str(evidence_type) if evidence_type is not None else None
        for route in self._routes.values():
            if route.matches_evidence_type(evidence_type_text) and route.accepts_media_type(media_type):
                return route

        if self._default_route_name is not None:
            return self._require_media_type(self._routes[self._default_route_name], media_type)

        if not self._routes:
            raise VerifierRouteError("No verifier route is registered")
        raise VerifierRouteError(
            f"No verifier route matches (evidence_type={evidence_type_text!r}, hint={hint!r}, "
            f"media_type={media_type!r}) and no default route was registered; "
            f"pass default=True on the route that should catch unmatched evidence"
        )

    @staticmethod
    def _require_media_type(route: VerifierRoute, media_type: str | None) -> VerifierRoute:
        """Return *route*, or raise when it does not accept *media_type*."""
        if route.accepts_media_type(media_type):
            return route
        raise VerifierRouteError(
            f"Route {route.name!r} does not accept media type {media_type!r} (accepts {sorted(route.accepts)})"
        )

    def get_nonce(
        self,
        size: int = 32,
        *,
        evidence_type: str | univ.ObjectIdentifier | None = None,
        hint: str | None = None,
    ) -> bytes:
        """Request a nonce from the selected route and remember the route."""
        route = self.resolve(evidence_type=evidence_type, hint=hint)
        nonce = route.verifier.get_nonce(size)
        if nonce:
            self._nonce_routes[nonce] = _NonceEntry(
                route_name=route.name,
                expires_at=time.monotonic() + self._nonce_ttl,
            )
        return nonce

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        *,
        nonce: bytes | None = None,
        evidence_type: str | univ.ObjectIdentifier | None = None,
        hint: str | None = None,
    ) -> VerifyResult:
        """Verify evidence with the route selected for the nonce or metadata."""
        route = self.resolve(evidence_type=evidence_type, hint=hint, nonce=nonce, media_type=media_type)
        result = route.verifier.verify_token(token_bytes, media_type, nonce)
        if nonce is not None:
            self._nonce_routes.pop(nonce, None)
        return result

    def verify_bundle(
        self,
        bundle: AttestationBundle | bytes,
        *,
        nonces: list[bytes | None] | None = None,
        hints: list[str | None] | None = None,
        media_types: list[str] | None = None,
    ) -> BundleVerifyResult:
        """Verify every statement in *bundle* and return per-statement verdicts.

        For each statement, the route is selected (in order):

        1. ``nonces[i]`` if provided and registered in the nonce table
           (this matches the existing single-token nonce-based dispatch).
        2. ``hints[i]`` if provided.
        3. The statement's type OID (only useful when exactly one route
           handles that OID).

        Parameters
        ----------
        bundle:
            Either a decoded :class:`AttestationBundle` or its DER bytes.
        nonces:
            Per-statement freshness nonces.  Length must match the number of
            statements; entries may be ``None`` for statements that do not
            need nonce-based routing.
        hints:
            Per-statement verifier hints (route names or base URLs).  Same
            length and ``None`` semantics as *nonces*.
        media_types:
            Per-statement media types passed to each verifier's
            ``verify_token``.  Defaults to the verifier's own
            ``media_type`` attribute when missing.

        Returns
        -------
        BundleVerifyResult
            Aggregated outcome with one :class:`VerifyResult` per statement
            and the parallel list of route names that were dispatched to.

        """
        if isinstance(bundle, (bytes, bytearray)):
            decoded = decode_attestation_bundle(bundle)
        else:
            decoded = bundle

        statements = list(decoded["attestations"])
        n = len(statements)

        if nonces is not None and len(nonces) != n:
            raise ValueError(f"nonces length {len(nonces)} does not match {n} statements")
        if hints is not None and len(hints) != n:
            raise ValueError(f"hints length {len(hints)} does not match {n} statements")
        if media_types is not None and len(media_types) != n:
            raise ValueError(f"media_types length {len(media_types)} does not match {n} statements")

        verdicts: list[VerifyResult] = []
        route_names: list[str] = []

        for i, statement in enumerate(statements):
            stmt_oid = str(statement["type"])
            # The Any field encodes as the inner DER plus the explicit ANY
            # tag-length prefix.  Strip the ANY wrapper: the encoded value
            # is identical to the raw bytes that prepare_*_attestation_statement
            # placed there.  pyasn1's Any encoder writes raw bytes directly,
            # so this is a no-op when the statement was built with our helpers.
            stmt_bytes = bytes(statement["stmt"])

            nonce = nonces[i] if nonces else None
            hint = hints[i] if hints else None
            media_type = media_types[i] if media_types else None

            try:
                # Only a caller-supplied media type is a wire fact; the fallback below is
                # read off the verifier itself, so gating on it would be a tautology.
                route = self.resolve(
                    evidence_type=stmt_oid,
                    hint=hint,
                    nonce=nonce,
                    media_type=media_type,
                )
            except VerifierRouteError as exc:
                logger.warning("Statement %d (oid=%s): no route — %s", i, stmt_oid, exc)
                verdicts.append(VerifyResult.unknown(f"no route for OID {stmt_oid}: {exc}"))
                route_names.append("")
                continue

            effective_media_type = media_type or getattr(route.verifier, "media_type", "application/octet-stream")
            verdict = route.verifier.verify_token(stmt_bytes, effective_media_type, nonce)
            verdicts.append(verdict)
            route_names.append(route.name)

            if nonce is not None:
                self._nonce_routes.pop(nonce, None)

            logger.debug(
                "Statement %d  oid=%s  route=%r  status=%s",
                i,
                stmt_oid,
                route.name,
                verdict.status.value,
            )

        return BundleVerifyResult(
            per_statement=tuple(verdicts),
            routes=tuple(route_names),
        )


def _declared_media_types(verifier: AttestationVerifier) -> frozenset[str]:
    """Return the media types *verifier* declares, or an empty set if it declares none."""
    return media_type_set(getattr(verifier, "accepts", None) or getattr(verifier, "media_type", None))


def _is_url_hint(hint: str) -> bool:
    parsed = urlparse(hint)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
