# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Protocol-agnostic Remote Attestation engine.

:class:`RemoteAttestationEngine` is the orchestration layer the MockCA (and any
other carrier) drives.  It owns the RA flow that used to live spread across the
MockCA's ``nonce_handler`` / ``rats_handler`` / ``attestation_verifier``:

1. :meth:`issue_nonce` — resolve the profile for a ``NonceRequest.reqTypeInfo.type``,
   build the type-specific response info, and issue a nonce in the
   :class:`NonceStore`.
2. :meth:`verify_bundle` — decode an ``AttestationBundle`` (libattest codec),
   and per statement: consume its nonce, resolve its profile, unwrap the
   statement, submit to the profile's verifier (with the profile's optional
   reference handler composed onto it), appraise the returned Attestation Result
   against the RA's acceptance policy, and aggregate per-statement verdicts + EAR
   JWTs.

The interface is deliberately **bytes / OID-strings / verdict objects** — never
a ``PKIMessage``.  The carrier extracts ``(bundle_der, tx_id)`` from its own
protocol and maps the returned verdict back to its own status codes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der
from libattest.formats.csrattest import (
    AttestationBundle,
    NonceResponse,
    NonceResponseTypeInfo,
    decode_attestation_bundle,
    get_attestation_bundle_certs,
    unwrap_attestation_statement,
)
from libattest.ra.nonce import BadNonceRequest, NonceState, NonceStore, ReplayError
from libattest.ra.ports import (
    OCTET_STREAM,
    AppraisalRequest,
    ReferenceCheckedVerifier,
    as_evidence_verifier,
)
from libattest.ra.profile import AttestationProfile
from libattest.ra.registry import ProfileRegistry
from libattest.ra.relying_party import EarAcceptancePolicy
from libattest.types import BundleVerifyResult, EarStatus, VerifyResult

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BundleVerifyOutcome:
    """Aggregated engine verdict for one bundle, plus the per-statement EAR JWTs.

    Attributes
    ----------
    result:
        The :class:`~libattest.types.BundleVerifyResult` with one
        :class:`~libattest.types.VerifyResult` per statement (in bundle order)
        and the parallel statement-OID list in ``routes``.
    ear_jwts:
        The EAR JWT carried by each affirming statement's verdict (``None`` for
        non-affirming or payload-less statements), parallel to
        ``result.per_statement``.  See :attr:`affirming_ears` for the
        ``(statement_oid, ear_jwt)`` list the RA's decision is actually over, and
        :attr:`ear_extensions` for every certificate extension it yields.

    """

    result: BundleVerifyResult
    ear_jwts: tuple[str | None, ...] = ()
    profiles: ProfileRegistry | None = None
    """The registry used to verify this bundle; resolves :attr:`ear_extensions`.
    ``None`` only for outcomes built without a registry (e.g. a bundle-decode
    failure before any statement was routed)."""

    @property
    def accepted(self) -> bool:
        """Return ``True`` iff every statement was affirmed (and at least one)."""
        return self.result.accepted

    @property
    def first_failure(self) -> VerifyResult | None:
        """Return the first non-affirming verdict, or ``None`` if all affirming."""
        return self.result.first_failure

    @property
    def first_ear(self) -> str | None:
        """Return the first affirming EAR JWT, or ``None`` when none affirmed."""
        for jwt in self.ear_jwts:
            if jwt:
                return jwt
        return None

    @property
    def affirming_ears(self) -> tuple[tuple[str, str], ...]:
        """Return ``(statement_oid, ear_jwt)`` for **every** affirming statement.

        A bundle may carry several statements — a platform quote and a key attestation,
        say — each appraised by its own verifier and each yielding its own Attestation
        Result.  The RA's decision is over that whole list, so it is exposed as a list;
        :attr:`first_ear` and :attr:`first_ear_extension` are the single-statement
        convenience views onto it.
        """
        return tuple((stmt_oid, jwt) for stmt_oid, jwt in zip(self.result.routes, self.ear_jwts) if jwt)

    @property
    def ear_extensions(self) -> tuple[tuple[str, bytes], ...]:
        """Return ``(extn_oid_dot, extn_value_der)`` for every affirming statement.

        Each affirming statement's profile is resolved via ``result.routes`` (the
        statement-OID list parallel to ``ear_jwts``) and its ``encode_ear_extension``
        called — the same per-type EAR/CMW choice the profile was built with.  Lets a
        carrier embed **all** the resulting certificate extensions without re-decoding
        the bundle or resolving profiles itself; previously only the first was
        reachable, so a second attestation in the same bundle was verified and then
        silently dropped on the way into the certificate.

        Statements whose profile no longer resolves are skipped (it should not happen
        for a bundle this engine itself just verified).
        """
        if self.profiles is None:
            return ()
        extensions: list[tuple[str, bytes]] = []
        for stmt_oid, jwt in self.affirming_ears:
            profile = self.profiles.by_statement(stmt_oid)
            if profile is not None:
                extensions.append(profile.encode_ear_extension(jwt))
        return tuple(extensions)

    @property
    def first_ear_extension(self) -> tuple[str, bytes] | None:
        """Return the first of :attr:`ear_extensions`, or ``None`` when there are none."""
        extensions = self.ear_extensions
        return extensions[0] if extensions else None


class RemoteAttestationEngine:
    """Drive nonce issuance and bundle verification over pluggable profiles.

    Parameters
    ----------
    profiles:
        The :class:`ProfileRegistry` binding OIDs to format codecs + services.
    nonce_store:
        The :class:`NonceStore` owning nonce lifecycle.  A fresh store is
        created when omitted (one nonce lifecycle per engine — no parallel
        nonce map).
    ear_policy:
        Optional :class:`~libattest.ra.relying_party.EarAcceptancePolicy`.  When set,
        every affirming verdict's EAR must satisfy it — signature against configured
        key material, freshness, and the RA-issued nonce — before the engine reports
        the statement as accepted.  ``None`` keeps the pre-existing behaviour of
        trusting whatever the verifier object returns, which is only safe when the
        verifier is in-process.

    """

    def __init__(
        self,
        profiles: ProfileRegistry,
        nonce_store: NonceStore | None = None,
        *,
        ear_policy: EarAcceptancePolicy | None = None,
    ) -> None:
        """Wire the engine to a profile registry, a nonce store, and an EAR policy."""
        self.profiles = profiles
        self.nonce_store = nonce_store if nonce_store is not None else NonceStore()
        self.ear_policy = ear_policy

    @classmethod
    def from_env(cls, nonce_store: NonceStore | None = None) -> RemoteAttestationEngine:
        """Build an engine whose :class:`ProfileRegistry` is wired from env vars.

        See :func:`libattest.ra.env.build_profile_registry_from_env` for the
        full list of environment variables consumed. A fresh :class:`NonceStore`
        is created when *nonce_store* is omitted.

        Raises
        ------
        RuntimeError
            No verifier routing is configured (see
            :func:`~libattest.ra.env.build_profile_registry_from_env`).

        """
        from libattest.ra.env import build_profile_registry_from_env  # noqa: PLC0415

        return cls(profiles=build_profile_registry_from_env(), nonce_store=nonce_store)

    # ── Phase 1: nonce issuance ────────────────────────────────────────────────

    def issue_nonce(
        self,
        tx_id: bytes,
        request_type_oid: str | None,
        *,
        req_info: bytes | None = None,
    ) -> NonceState:
        """Issue a nonce for a ``NonceRequest`` of type *request_type_oid*.

        Resolves the profile by ``request_type_oid``; the nonce is stored under
        the profile's ``statement_oid`` so evidence-side dispatch (which only
        sees ``AttestationStatement.type``) finds it.  When a profile is found,
        the client-proposed ``hashAlgId`` is parsed from *req_info* and a
        type-specific ``respInfo`` is built and attached to the nonce state.

        A request type with no registered profile (or an absent type) is stored
        positionally (under ``statement_oid=None``) with no respInfo.

        Parameters
        ----------
        tx_id:
            Transaction identifier the nonce is filed under.
        request_type_oid:
            Dot-form ``NonceRequest.reqTypeInfo.type`` OID, or ``None``.
        req_info:
            Optional DER ``NonceRequest.reqTypeInfo.reqInfo`` carrying
            negotiation params.

        Returns
        -------
        NonceState
            The issued nonce state (``nonce`` + optional ``resp_info``).

        """
        profile = self.profiles.by_request_type(request_type_oid)
        if profile is None:
            # No profile: store under the request type itself when present, else
            # positionally under None.
            statement_oid = str(request_type_oid) if request_type_oid else None
            return self.nonce_store.issue(tx_id, statement_oid)

        # One hook, whether the provisioning is a pure function of the client's reqInfo
        # or the result of a verifier round-trip — see AttestationProfile.build_verifier_info.
        provisioning = profile.build_verifier_info(req_info)
        logger.info(
            "RA engine: provisioning %s for statement oid=%s (sessionId=%s, respInfo=%dB)",
            provisioning.label,
            profile.statement_oid,
            provisioning.session_id,
            len(provisioning.resp_info) if provisioning.resp_info else 0,
        )
        return self.nonce_store.issue(
            tx_id,
            profile.statement_oid,
            resp_info=provisioning.resp_info,
            session_id=provisioning.session_id,
        )

    def build_nonce_response(
        self,
        tx_id: bytes,
        request_type_oid: str | None,
        *,
        req_info: bytes | None = None,
        requested_len: int | None = None,
        min_nonce_length: int | None = 32,
        expiry_time: int | None = None,
    ) -> NonceResponse:
        """Validate the request, issue a nonce, and build a complete ``NonceResponse``.

        Wraps :meth:`issue_nonce` with the wire-level concerns a carrier would
        otherwise duplicate: minimum-length validation and packaging the result
        as a ``NonceResponse`` ASN.1 value.

        Critically, ``respTypeInfo.type`` is set to the resolved profile's
        ``response_type_oid`` — **not** *request_type_oid* echoed back. Request
        and response are distinct wire positions (see
        :attr:`~libattest.ra.profile.AttestationProfile.response_type_oid`); a
        profile whose response OID differs from its request OID (the TPM quote
        profile) is packaged correctly without the carrier needing to know that.
        When no profile resolves for *request_type_oid*, the response type falls
        back to echoing the request type (unregistered-OID passthrough).

        Parameters
        ----------
        tx_id:
            Transaction identifier the nonce is filed under.
        request_type_oid:
            Dot-form ``NonceRequest.reqTypeInfo.type`` OID, or ``None``.
        req_info:
            Optional DER ``NonceRequest.reqTypeInfo.reqInfo``.
        requested_len:
            The client's requested nonce length (``NonceRequest.len``), or
            ``None`` when omitted. Validated against *min_nonce_length* only —
            the issued nonce's actual length is the store's configured size
            (constant per deployment); this field does not resize it.
        min_nonce_length:
            Minimum acceptable *requested_len*. ``None`` skips the check.
        expiry_time:
            ``NonceResponse.expiry`` in seconds.  Defaults to the lifetime the nonce
            store actually enforces, so the attester is told the deadline the RA will
            hold it to; previously it defaulted to *absent*, which advertised no
            deadline at all while a 300s TTL was being enforced.  Pass ``0`` to omit
            the field.

        Returns
        -------
        NonceResponse
            Ready to DER-encode into the carrier's reply.

        Raises
        ------
        BadNonceRequest
            *requested_len* is below *min_nonce_length*.

        """
        if requested_len is not None and min_nonce_length is not None and requested_len < min_nonce_length:
            raise BadNonceRequest(
                f"Requested nonce length {requested_len} is less than minimum length {min_nonce_length}."
            )

        state = self.issue_nonce(tx_id, request_type_oid, req_info=req_info)

        profile = self.profiles.by_request_type(request_type_oid)
        response_type_oid = profile.response_type_oid if profile is not None else request_type_oid

        response = NonceResponse()
        response["nonce"] = state.nonce
        expiry = self.nonce_store.ttl_seconds if expiry_time is None else expiry_time
        if expiry:
            response["expiry"] = expiry
        if response_type_oid is not None:
            resp_type_info = NonceResponseTypeInfo()
            resp_type_info["type"] = univ.ObjectIdentifier(response_type_oid)
            if state.resp_info is not None:
                resp_type_info["respInfo"] = univ.Any(state.resp_info)
            response["respTypeInfo"] = resp_type_info
        return response

    # ── Phase 3: bundle verification ───────────────────────────────────────────

    def verify_bundle(
        self,
        bundle_der: bytes,
        tx_id: bytes,
        *,
        pubkey: bytes | None = None,
        drop_transaction: bool = True,
    ) -> BundleVerifyOutcome:
        """Verify every statement in *bundle_der* and aggregate the verdicts.

        For each statement (in bundle order):

        1. Consume its nonce (OID-keyed first, positional fallback) from the
           store.
        2. Resolve its profile by ``statement_oid``.
        3. Unwrap the ``stmt`` open type via ``profile.unwrap_statement`` (or the
           libattest default when no profile).
        4. Submit to the profile's verifier, with the profile's reference handler
           (if any) composed onto it — a rejecting reference check downgrades an
           otherwise-affirming verdict to contraindicated.
        5. Appraise the returned Attestation Result against :attr:`ear_policy`,
           when one is configured.

        Parameters
        ----------
        bundle_der:
            DER of the ``AttestationBundle``.
        tx_id:
            Transaction identifier whose nonces gate this bundle.
        pubkey:
            To-be-certified SubjectPublicKeyInfo DER extracted from the CMP carrier
            by the caller (not carried in the bundle). Required for key-attestation
            profiles so the verifier can bind the certified TPM key to the CSR key;
            ignored by quote/jwt profiles.
        drop_transaction:
            When ``True`` (default), the per-tx nonce state is dropped after
            verification (success or failure) so memory is freed and a retried
            transaction starts clean.

        Returns
        -------
        BundleVerifyOutcome
            Per-statement verdicts + EAR JWTs; ``.accepted`` is ``True`` iff
            every statement affirmed.

        """
        try:
            return self._verify_bundle(bundle_der, tx_id, pubkey=pubkey)
        finally:
            if drop_transaction:
                self.nonce_store.drop_transaction(tx_id)

    def _verify_bundle(self, bundle_der: bytes, tx_id: bytes, *, pubkey: bytes | None = None) -> BundleVerifyOutcome:
        try:
            bundle = decode_attestation_bundle(bundle_der)
        except ValueError as exc:
            logger.warning("RA engine: AttestationBundle decode failed: %s", exc)
            verdict = VerifyResult.unknown(f"bundle decode failed: {exc}")
            return BundleVerifyOutcome(
                result=BundleVerifyResult(per_statement=(verdict,), routes=("",)),
                ear_jwts=(None,),
            )

        statements = list(bundle["attestations"])
        endorsements = _bundle_endorsements(bundle)
        verdicts: list[VerifyResult] = []
        route_oids: list[str] = []
        ear_jwts: list[str | None] = []

        per_oid_counter: dict[str | None, int] = {}
        total_position = 0

        for stmt in statements:
            stmt_oid = str(stmt["type"])
            oid_instance = per_oid_counter.get(stmt_oid, 0)
            per_oid_counter[stmt_oid] = oid_instance + 1
            positional_instance = total_position
            total_position += 1

            profile = self.profiles.by_statement(stmt_oid)

            # 1. Consume the nonce (OID-keyed first, positional fallback).
            try:
                nonce_state = self._consume_nonce(tx_id, stmt_oid, oid_instance, positional_instance)
            except _NonceError as exc:
                logger.warning("RA engine: statement oid=%s — %s", stmt_oid, exc)
                verdicts.append(VerifyResult.unknown(str(exc)))
                route_oids.append(stmt_oid)
                ear_jwts.append(None)
                continue

            # 2. Unwrap the statement open type.
            stmt_raw = bytes(stmt["stmt"])
            unwrap = profile.unwrap_statement if profile is not None else unwrap_attestation_statement
            try:
                stmt_bytes, _is_wrapped = unwrap(stmt_raw)
            except ValueError as exc:
                logger.warning("RA engine: statement oid=%s unwrap failed: %s", stmt_oid, exc)
                verdicts.append(VerifyResult.contraindicated(f"stmt unwrap failed: {exc}"))
                route_oids.append(stmt_oid)
                ear_jwts.append(None)
                continue

            if profile is None:
                logger.warning("RA engine: no profile for statement oid=%s", stmt_oid)
                verdicts.append(VerifyResult.unknown(f"no profile for OID {stmt_oid}"))
                route_oids.append(stmt_oid)
                ear_jwts.append(None)
                continue

            # 3. Submit to the verifier (with its reference-value check composed on).
            verdict = self._submit(
                profile, nonce_state, stmt_oid, stmt_bytes, bundle_der, endorsements=endorsements, pubkey=pubkey
            )

            # 4. Appraise the Attestation Result itself (RFC 9334 Relying Party).
            verdict = self._appraise_ear(profile, verdict, nonce_state.nonce)

            verdicts.append(verdict)
            route_oids.append(stmt_oid)
            ear_jwts.append(verdict.payload if (verdict.accepted and isinstance(verdict.payload, str)) else None)

        result = BundleVerifyResult(per_statement=tuple(verdicts), routes=tuple(route_oids))
        return BundleVerifyOutcome(result=result, ear_jwts=tuple(ear_jwts), profiles=self.profiles)

    # ── Verifier submission ────────────────────────────────────────────────────

    def _submit(
        self,
        profile: AttestationProfile,
        nonce_state: NonceState,
        stmt_oid: str,
        stmt_bytes: bytes,
        bundle_der: bytes,
        *,
        endorsements: tuple[bytes, ...] = (),
        pubkey: bytes | None = None,
    ) -> VerifyResult:
        """Submit one statement to its profile's verifier and return the verdict.

        Everything the RA knows about the statement — the containing bundle, the
        negotiated ``respInfo``, the key-attestation session id and subject key — goes
        into one :class:`~libattest.ra.ports.AppraisalRequest`.  The engine no longer
        names a concrete verifier class, so a custom verifier that implements
        :meth:`~libattest.ra.ports.EvidenceVerifier.appraise` receives the full context;
        one implementing only the older ``verify_token`` ABC is adapted transparently by
        :func:`~libattest.ra.ports.as_evidence_verifier`.
        """
        verifier = profile.resolve_verifier()
        # The RA cannot learn the Evidence media type from the wire — an
        # AttestationStatement carries a type OID, not a media type — so the deployment
        # declares it on the profile.  Falling back to the verifier's own declaration
        # asks the appraiser what it is appraising, which is only ever a guess.
        media_type = profile.media_type or getattr(verifier, "media_type", OCTET_STREAM)

        if profile.binds_subject_key and not pubkey:
            return VerifyResult.contraindicated("key attestation requires the to-be-certified SubjectPublicKeyInfo")

        port = as_evidence_verifier(verifier)
        if profile.reference_handler is not None:
            port = ReferenceCheckedVerifier(port, profile.reference_handler)

        request = AppraisalRequest(
            evidence=stmt_bytes,
            media_type=media_type,
            nonce=nonce_state.nonce,
            statement_oid=stmt_oid,
            # Least authority per statement: the whole container goes only to a verifier
            # that says it parses one, and the CSR key only to a profile that binds it.
            # Everyone else gets this statement, its endorsements, and nothing more.
            bundle=bundle_der if getattr(verifier, "needs_bundle", False) else None,
            endorsements=endorsements,
            resp_info=self._resp_info_json(profile, nonce_state.resp_info),
            subject_key=pubkey if profile.binds_subject_key else None,
            session_id=nonce_state.session_id,
        )
        return port.appraise(request)

    def _appraise_ear(self, profile: AttestationProfile, verdict: VerifyResult, nonce: bytes) -> VerifyResult:
        """Apply the configured EAR acceptance policy to an affirming verdict.

        Only an affirming verdict carrying an EAR JWT is appraised: a verdict that has
        already failed needs no second opinion, and a verifier that returns no token
        gives the RA nothing to appraise — that is reported as a rejection rather than
        waved through, because a configured policy means the RA has been told not to
        act on a verdict it cannot check.
        """
        if self.ear_policy is None or verdict.status != EarStatus.affirming:
            return verdict
        if not isinstance(verdict.payload, str) or not verdict.payload:
            return VerifyResult.contraindicated(
                f"verifier affirmed statement oid={profile.statement_oid} without an EAR to appraise"
            )
        decision = self.ear_policy.appraise(
            verdict.payload,
            expected_nonce=nonce,
            anchor=profile.ear_anchor,
            verifier_id=profile.verifier_id,
        )
        return decision.result

    @staticmethod
    def _resp_info_json(profile: AttestationProfile, resp_info_der: bytes | None) -> dict | None:
        """Serialise a DER ``respInfo`` to JSON via the profile codec, or ``None``."""
        if not resp_info_der:
            return None
        try:
            return profile.resp_info_to_json(resp_info_der)
        except Exception as exc:  # noqa: BLE001 — a bad codec must not drop evidence
            logger.warning(
                "RA engine: resp_info_to_json failed for oid=%s: %s",
                profile.statement_oid,
                exc,
            )
            return None

    # ── Nonce consume (OID → positional fallback) ──────────────────────────────

    def _consume_nonce(
        self,
        tx_id: bytes,
        stmt_oid: str,
        oid_instance: int,
        positional_instance: int,
    ) -> NonceState:
        """Consume the nonce for a statement, OID-keyed with a positional fallback.

        The bundle's ``AttestationStatement.type`` always carries an OID, but
        ``NonceRequest.reqTypeInfo`` is optional: a typeless request files the
        nonce under ``(None, position)`` instead of ``(oid, instance)``.

        Raises
        ------
        _NonceError
            On any final lookup failure (missing, expired, or replayed).

        """
        try:
            return self.nonce_store.consume(tx_id, stmt_oid, oid_instance)
        except KeyError:
            pass  # fall through to positional lookup
        except ValueError as exc:
            raise _NonceError(f"nonce expired for oid={stmt_oid} instance={oid_instance}: {exc}") from exc
        except ReplayError as exc:
            raise _NonceError(
                f"nonce already consumed (replay) for oid={stmt_oid} instance={oid_instance}: {exc}"
            ) from exc

        try:
            return self.nonce_store.consume(tx_id, None, positional_instance)
        except KeyError as exc:
            raise _NonceError(
                f"no nonce for statement oid={stmt_oid} "
                f"(oid-instance={oid_instance}, positional={positional_instance}): {exc}"
            ) from exc
        except ValueError as exc:
            raise _NonceError(f"nonce expired (positional={positional_instance}): {exc}") from exc
        except ReplayError as exc:
            raise _NonceError(f"nonce already consumed (positional={positional_instance}): {exc}") from exc


def _bundle_endorsements(bundle: AttestationBundle) -> tuple[bytes, ...]:
    """Return the bundle's ``certs`` as DER, decoded once for the whole bundle.

    These are the Endorsements of RFC 9334 §3 — the AK/EK certificate chain vouching
    for the Attester.  They used to be reachable only by re-parsing the container, which
    is why every verifier was handed the whole bundle; extracting them here means a
    verifier that only needs the chain never sees the other statements in it.

    A bundle carrying a non-X.509 ``otherCert`` entry yields no endorsements rather than
    raising: an unsupported endorsement format must not sink an otherwise valid bundle.
    """
    try:
        certs = get_attestation_bundle_certs(bundle)
    except NotImplementedError as exc:
        logger.info("RA engine: bundle carries unsupported endorsement entries: %s", exc)
        return ()
    return tuple(encode_to_der(cert) for cert in certs)


class _NonceError(Exception):
    """Internal: any nonce-consume failure, mapped to an ``unknown`` verdict."""


__all__ = [
    "BundleVerifyOutcome",
    "RemoteAttestationEngine",
]
