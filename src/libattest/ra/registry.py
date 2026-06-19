# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Profile and service registries for the RA engine.

Two registries make a new attestation type — and a swapped Verifier or
ReferenceValue service — a *registration*, never a core edit:

* :class:`ProfileRegistry` indexes :class:`~libattest.ra.profile.AttestationProfile`
  objects by both their ``request_type_oid`` (nonce-issue side) and their
  ``statement_oid`` (evidence side), mirroring the MockCA
  ``AttestationRouteRegistry``.
* :class:`ServiceRegistry` is the **replaceability seam**: a developer registers
  a custom :class:`~libattest.verifier.base.AttestationVerifier` and/or a custom
  :class:`~libattest.verifier.reference.VerifierReferenceHandler` by OID/name.
  Profiles built via :meth:`ProfileRegistry.build_profile` then pull their
  services from this registry, so attaching a new verifier + reference handler
  for a new OID needs no change to the engine or the profile dataclass.

Constructor injection still works everywhere: an
:class:`AttestationProfile` can carry an explicit ``verifier`` /
``reference_handler`` instance, bypassing the service registry entirely.
"""

from __future__ import annotations

import logging

from libattest.ra.profile import AttestationProfile
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.reference import VerifierReferenceHandler

logger = logging.getLogger(__name__)


class ProfileRegistry:
    r"""Resolve :class:`AttestationProfile`\ s by request-type or statement OID.

    Both lookup directions are needed:

    * :meth:`by_request_type` — the nonce-issue side maps a ``NonceRequest.type``
      to the statement OID under which the nonce is stored and to the respInfo
      builder.
    * :meth:`by_statement` — the evidence-dispatch side maps an
      ``AttestationStatement.type`` to the verifier, reference handler, and
      respInfo-JSON serialiser.

    Build the registry once at startup; lookups are read-only afterwards.
    """

    def __init__(self) -> None:
        """Initialise empty request-type and statement indexes."""
        self._by_request: dict[str, AttestationProfile] = {}
        self._by_statement: dict[str, AttestationProfile] = {}

    def register(self, profile: AttestationProfile) -> AttestationProfile:
        """Register *profile*, indexing it by both OIDs.

        Re-registering an already-known OID overwrites the prior profile (so a
        deployment can refine a built-in one).  Returns the registered profile
        for fluent use.
        """
        self._by_request[str(profile.request_type_oid)] = profile
        self._by_statement[str(profile.statement_oid)] = profile
        logger.info(
            "AttestationProfile registered: request_type=%s statement=%s",
            profile.request_type_oid,
            profile.statement_oid,
        )
        return profile

    def by_request_type(self, oid) -> AttestationProfile | None:
        """Return the profile whose ``request_type_oid`` is *oid*, or ``None``."""
        if not oid:
            return None
        return self._by_request.get(str(oid))

    def by_statement(self, oid) -> AttestationProfile | None:
        """Return the profile whose ``statement_oid`` is *oid*, or ``None``."""
        if not oid:
            return None
        return self._by_statement.get(str(oid))

    def request_type_oids(self) -> list[str]:
        """Return the registered request-type OIDs (dot form)."""
        return sorted(self._by_request)

    def statement_oids(self) -> list[str]:
        """Return the registered statement OIDs (dot form)."""
        return sorted(self._by_statement)

    def snapshot(self) -> dict:
        """Debugging snapshot: request-type OID → statement OID."""
        return {req: profile.statement_oid for req, profile in self._by_request.items()}


class ServiceRegistry:
    """Registry of swappable verifier and reference-value services keyed by name.

    A name is normally a dot-form OID (the statement OID a service appraises),
    but any string works.  This is the single place a developer plugs in a new
    :class:`AttestationVerifier` or :class:`VerifierReferenceHandler`; the engine
    and profiles read from here, so no core code changes when a service is
    replaced.
    """

    def __init__(self) -> None:
        """Initialise empty verifier and reference-handler maps."""
        self._verifiers: dict[str, AttestationVerifier] = {}
        self._reference_handlers: dict[str, VerifierReferenceHandler] = {}

    # ── Verifiers ──────────────────────────────────────────────────────────────

    def register_verifier(self, name, verifier: AttestationVerifier) -> AttestationVerifier:
        """Register *verifier* under *name* (an OID/name string)."""
        if not isinstance(verifier, AttestationVerifier):
            raise TypeError("verifier must implement the AttestationVerifier ABC")
        self._verifiers[str(name)] = verifier
        logger.info("ServiceRegistry: registered verifier for %s (%s)", name, type(verifier).__name__)
        return verifier

    def get_verifier(self, name) -> AttestationVerifier | None:
        """Return the verifier registered under *name*, or ``None``."""
        if not name:
            return None
        return self._verifiers.get(str(name))

    # ── Reference handlers ─────────────────────────────────────────────────────

    def register_reference_handler(self, name, handler: VerifierReferenceHandler) -> VerifierReferenceHandler:
        """Register reference-value *handler* under *name* (an OID/name string)."""
        if not isinstance(handler, VerifierReferenceHandler):
            raise TypeError("handler must implement the VerifierReferenceHandler ABC")
        self._reference_handlers[str(name)] = handler
        logger.info("ServiceRegistry: registered reference handler for %s (%s)", name, type(handler).__name__)
        return handler

    def get_reference_handler(self, name) -> VerifierReferenceHandler | None:
        """Return the reference handler registered under *name*, or ``None``."""
        if not name:
            return None
        return self._reference_handlers.get(str(name))

    def snapshot(self) -> dict:
        """Debugging snapshot: which names carry a verifier / reference handler."""
        return {
            "verifiers": sorted(self._verifiers),
            "reference_handlers": sorted(self._reference_handlers),
        }


__all__ = [
    "ProfileRegistry",
    "ServiceRegistry",
]
