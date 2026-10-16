# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal attester-side client logic."""

from __future__ import annotations

import logging
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from pyasn1.type import univ

from libattest.attester.claim_release import ClaimReleasePolicy, release_claims
from libattest.attester.verifier_info import VerifierInfo, parse_verifier_info
from libattest.formats.csrattest import (
    AttestationBundle,
    NonceResponse,
    nonce_response_type_oid,
    prepare_attestation_bundle,
    prepare_multi_statement_bundle,
    prepare_opaque_attestation_statement,
)
from libattest.formats.csrattest.csr_attest_structures import pem_chain_to_cmp_certs
from libattest.types import AttestResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvidenceRequest:
    """Everything the attester knows when it is asked to produce one Evidence statement.

    A provider used to be handed a bare nonce, which is only enough for Evidence whose
    every other parameter is compiled in.  It is not enough to encrypt Evidence to a
    verifier whose key arrives at run time, to honour the PCR set the RA actually
    promised to appraise, or to decide what this particular verifier is allowed to
    learn — all three are properties of *this exchange*, not of the provider.

    Attributes
    ----------
    nonce:
        The RA-issued freshness nonce, or ``None`` when the RA asked for none.
    verifier_info:
        What the ``NonceResponse`` provisioned — see
        :class:`~libattest.attester.verifier_info.VerifierInfo`.
    verifier_id:
        The deployment's name for the verifier, when the attester knows it; the key
        :class:`~libattest.attester.claim_release.ClaimReleasePolicy` decides against.
    media_type:
        The media type the Evidence should be produced in, when the caller knows it.
    claim_policy:
        What this attester will release to this verifier.  ``None`` releases everything.

    """

    nonce: bytes | None = None
    verifier_info: VerifierInfo | None = None
    verifier_id: str | None = None
    media_type: str | None = None
    claim_policy: ClaimReleasePolicy | None = None

    def release(self, claims: Mapping[str, Any]) -> dict[str, Any]:
        """Return the subset of *claims* this request's policy releases."""
        return release_claims(claims, self.claim_policy, verifier_id=self.verifier_id)


class AttesterProvider(Protocol):
    """Provider interface for evidence generators."""

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Generate evidence bound to an optional freshness nonce."""
        ...


def resolve_evidence_generation_inputs(
    nonce_response: NonceResponse,
    provider_oids: Collection[str],
    oid: str | univ.ObjectIdentifier | None = None,
) -> tuple[str, bytes]:
    """Return the Evidence OID and nonce selected for CMP evidence generation.

    ``NonceResponse.respTypeInfo.type`` selects the syntax of ``respInfo``; it
    does not generally identify the Evidence statement that an Attester must
    produce.  An explicit *oid* therefore takes precedence, and an omitted OID
    is inferred only when exactly one Evidence provider is registered.
    """
    nonce = bytes(nonce_response["nonce"])
    if not nonce:
        raise ValueError("CMP NonceResponse contains an empty nonce")

    if oid is not None:
        return str(oid), nonce
    if len(provider_oids) == 1:
        return next(iter(provider_oids)), nonce

    response_oid = nonce_response_type_oid(nonce_response)
    if response_oid is None:
        raise ValueError(
            "evidence OID is required when a CMP NonceResponse has no type field and multiple providers are registered"
        )
    raise ValueError(
        "evidence OID is required when multiple providers are registered; "
        f"CMP NonceResponse response type {response_oid!r} selects respInfo, not Evidence"
    )


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

    def generate_evidence(
        self,
        oid: str | univ.ObjectIdentifier,
        nonce: bytes | None = None,
        *,
        request: EvidenceRequest | None = None,
    ) -> AttestResult:
        """Generate evidence for the selected OID.

        A provider that accepts the wider :class:`EvidenceRequest` — it exposes
        ``generate_evidence_for`` — is given the whole exchange; one that implements
        only the original ``generate_evidence(nonce)`` still sees just the nonce.  The
        capability is duck-typed rather than declared, exactly as the RA does for
        verifiers, so no existing provider has to change to keep working.
        """
        oid_text = str(oid)
        try:
            provider = self._providers[oid_text]
        except KeyError as exc:
            raise KeyError(f"No attester provider registered for OID {oid_text!r}") from exc

        generate_for: Callable[[EvidenceRequest], AttestResult] | None = getattr(
            provider, "generate_evidence_for", None
        )
        if callable(generate_for):
            result = generate_for(request if request is not None else EvidenceRequest(nonce=nonce))
        else:
            result = provider.generate_evidence(request.nonce if request is not None else nonce)
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
        *,
        verifier_id: str | None = None,
        claim_policy: ClaimReleasePolicy | None = None,
    ) -> AttestResult:
        """Generate evidence from a decoded CMP attestation freshness response.

        *oid* is an Evidence statement OID.  It is required when multiple
        providers are registered because ``respTypeInfo.type`` selects the
        response payload syntax rather than Evidence.

        The response's verifier information is parsed once here and handed to the
        provider as an :class:`EvidenceRequest`, so a provider never has to re-decode
        the ``NonceResponse`` to find the key it must encrypt to.
        """
        selected_oid, nonce = resolve_evidence_generation_inputs(nonce_response, self._providers, oid)
        request = EvidenceRequest(
            nonce=nonce,
            verifier_info=parse_verifier_info(nonce_response),
            verifier_id=verifier_id,
            claim_policy=claim_policy,
        )
        return self.generate_evidence(selected_oid, nonce, request=request)

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
