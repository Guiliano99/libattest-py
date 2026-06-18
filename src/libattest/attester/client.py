# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal attester-side client logic."""

import logging
from typing import Protocol

from pyasn1.type import univ

from libattest.formats.csrattest import (
    AttestationBundle,
    NonceResponse,
    prepare_attestation_bundle,
    prepare_multi_statement_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.formats.csrattest.csr_attest_structures import pem_chain_to_cmp_certs
from libattest.types import AttestResult

logger = logging.getLogger(__name__)


class AttesterProvider(Protocol):
    """Provider interface for evidence generators."""

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Generate evidence bound to an optional freshness nonce."""


class AttesterClient:
    """Dispatch evidence generation to registered providers."""

    def __init__(self, providers: dict[str, AttesterProvider] | None = None) -> None:
        """Initialize the registry, optionally pre-loading providers keyed by OID."""
        self._providers = dict(providers or {})

    @property
    def providers(self) -> dict[str, AttesterProvider]:
        """Return registered providers keyed by evidence OID."""
        return dict(self._providers)

    def register_provider(self, oid: str | univ.ObjectIdentifier, provider: AttesterProvider) -> None:
        """Register a provider for one evidence type OID."""
        self._providers[str(oid)] = provider

    def generate_evidence(self, oid: str | univ.ObjectIdentifier, nonce: bytes | None = None) -> AttestResult:
        """Generate evidence for the selected OID."""
        oid_text = str(oid)
        try:
            provider = self._providers[oid_text]
        except KeyError as exc:
            raise KeyError(f"No attester provider registered for OID {oid_text!r}") from exc

        result = provider.generate_evidence(nonce)
        if result.oid != oid_text:
            raise ValueError(f"Provider for OID {oid_text!r} returned evidence for {result.oid!r}")
        return result

    def generate_all_evidence(
        self,
        nonce: bytes | None = None,
        nonces_by_oid: dict[str, bytes] | None = None,
    ) -> list[AttestResult]:
        """Generate evidence from every registered provider.

        Pass *nonces_by_oid* to bind each provider to its own freshness
        nonce (required when each verifier issues its own nonce, e.g. for
        multi-TPM flows).  When unset, *nonce* is shared across all
        providers.
        """
        results = []
        for oid in self._providers:
            n = (nonces_by_oid or {}).get(oid, nonce)
            results.append(self.generate_evidence(oid, n))
        return results

    def generate_evidence_from_nonce_response(
        self,
        nonce_response: NonceResponse,
        oid: str | univ.ObjectIdentifier | None = None,
    ) -> AttestResult:
        """Generate evidence from a decoded CMP attestation freshness response."""
        nonce = bytes(nonce_response["nonce"])
        if not nonce:
            raise ValueError("CMP NonceResponse contains an empty nonce")

        selected_oid = str(oid) if oid is not None else None
        if selected_oid is None and nonce_response["type"].isValue:
            selected_oid = str(nonce_response["type"])
        if selected_oid is None and len(self._providers) == 1:
            selected_oid = next(iter(self._providers))
        if selected_oid is None:
            raise ValueError("oid is required when CMP NonceResponse has no type field")

        return self.generate_evidence(selected_oid, nonce)

    @staticmethod
    def prepare_attestation_bundle(result: AttestResult) -> AttestationBundle:
        """Wrap an attestation result in a one-statement ``AttestationBundle``.

        If ``result.cert_chain`` is set to a PEM file path or PEM string,
        the certificates are decoded and included in the bundle's ``certs``
        field.
        """
        statement = prepare_opaque_attestation_statement(
            univ.ObjectIdentifier(result.oid),
            result.evidence_bytes(),
        )

        certs = None
        if result.cert_chain is not None:
            try:
                certs = pem_chain_to_cmp_certs(result.cert_chain)
                logger.debug("Including %d cert(s) from cert_chain in bundle", len(certs))
            except Exception as exc:
                logger.warning("Could not parse cert_chain; omitting from bundle: %s", exc)

        return prepare_attestation_bundle([statement], certs=certs)

    @staticmethod
    def prepare_multi_statement_bundle(
        results: list[AttestResult],
    ) -> AttestationBundle:
        """Pack multiple :class:`AttestResult` items into one ``AttestationBundle``.

        Each result becomes one ``AttestationStatement`` whose evidence is
        wrapped as an opaque OCTET STRING.

        If any result carries a ``cert_chain``, those certs are merged into
        the bundle's ``certs`` field (deduplication is the caller's
        responsibility — duplicates are kept verbatim).

        Use this for multi-evidence flows (e.g. evidence from two TPMs, or
        a TPM + an EAT JWT in the same enrollment).
        """
        if not results:
            raise ValueError("prepare_multi_statement_bundle: results must be non-empty")

        certs: list = []
        for result in results:
            if result.cert_chain is None:
                continue
            try:
                certs.extend(pem_chain_to_cmp_certs(result.cert_chain))
            except Exception as exc:
                logger.warning(
                    "Could not parse cert_chain for OID %s; skipping: %s",
                    result.oid,
                    exc,
                )
        cert_chain = certs if certs else None

        logger.debug(
            "Building multi-statement bundle: %d statements, %d certs",
            len(results),
            len(cert_chain) if cert_chain else 0,
        )
        return prepare_multi_statement_bundle(results, certs=cert_chain)
