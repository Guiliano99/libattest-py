# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Protocol-agnostic Remote Attestation engine.

:class:`RemoteAttestationEngine` is the orchestration layer the MockCA (and any
other carrier) drives.  It owns the RA flow that used to live spread across the
MockCA's ``nonce_handler`` / ``rats_handler`` / ``attestation_verifier``:

1. :meth:`issue_nonce` — resolve the profile for a ``NonceRequest.type``, build
   the type-specific ``respInfo``, and issue a nonce in the :class:`NonceStore`.
2. :meth:`verify_bundle` — decode an ``AttestationBundle`` (libattest codec),
   and per statement: consume its nonce, resolve its profile, unwrap the
   statement, submit to the profile's verifier, run the optional reference
   handler, and aggregate per-statement verdicts + EAR JWTs.

The interface is deliberately **bytes / OID-strings / verdict objects** — never
a ``PKIMessage``.  The carrier extracts ``(bundle_der, tx_id)`` from its own
protocol and maps the returned verdict back to its own status codes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from libattest.formats.csrattest import (
    decode_attestation_bundle,
    unwrap_attestation_statement,
)
from libattest.ra.nonce import NonceState, NonceStore, ReplayError
from libattest.ra.profile import AttestationProfile
from libattest.ra.registry import ProfileRegistry
from libattest.ra.verifier_client import VeraisonVerifierClient
from libattest.types import BundleVerifyResult, EarStatus, VerifyResult
from libattest.verifier.base import AttestationVerifier

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
        ``result.per_statement``.

    """

    result: BundleVerifyResult
    ear_jwts: tuple[str | None, ...] = ()

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

    """

    def __init__(
        self,
        profiles: ProfileRegistry,
        nonce_store: NonceStore | None = None,
    ) -> None:
        """Wire the engine to a profile registry and (optionally) a nonce store."""
        self.profiles = profiles
        self.nonce_store = nonce_store if nonce_store is not None else NonceStore()

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
            Dot-form ``NonceRequest.type`` OID, or ``None``.
        req_info:
            Optional DER ``NonceRequest.reqInfo`` carrying negotiation params.

        Returns
        -------
        NonceState
            The issued nonce state (``nonce`` + optional ``resp_info``).

        """
        profile = self.profiles.by_request_type(request_type_oid)
        statement_oid: str | None
        resp_info: bytes | None = None
        if profile is not None:
            statement_oid = profile.statement_oid
            proposed = profile.parse_req_info(req_info)
            resp_info = profile.build_resp_info(proposed)
            if resp_info is not None:
                logger.info(
                    "RA engine: attaching %s respInfo for statement oid=%s (%dB)",
                    profile.resp_info_label,
                    statement_oid,
                    len(resp_info),
                )
        else:
            # No profile: store under the request type itself when present, else
            # positionally under None.
            statement_oid = str(request_type_oid) if request_type_oid else None

        return self.nonce_store.issue(tx_id, statement_oid, resp_info=resp_info)

    # ── Phase 3: bundle verification ───────────────────────────────────────────

    def verify_bundle(
        self,
        bundle_der: bytes,
        tx_id: bytes,
        *,
        drop_transaction: bool = True,
    ) -> BundleVerifyOutcome:
        """Verify every statement in *bundle_der* and aggregate the verdicts.

        For each statement (in bundle order):

        1. Consume its nonce (OID-keyed first, positional fallback) from the
           store.
        2. Resolve its profile by ``statement_oid``.
        3. Unwrap the ``stmt`` open type via ``profile.unwrap_statement`` (or the
           libattest default when no profile).
        4. Submit to the profile's verifier (forwarding the evidence OID and the
           JSON respInfo when the verifier is the default HTTP client).
        5. Run the profile's reference handler, if any; a rejecting reference
           check downgrades an otherwise-affirming verdict to contraindicated.

        Parameters
        ----------
        bundle_der:
            DER of the ``AttestationBundle``.
        tx_id:
            Transaction identifier whose nonces gate this bundle.
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
            return self._verify_bundle(bundle_der, tx_id)
        finally:
            if drop_transaction:
                self.nonce_store.drop_transaction(tx_id)

    def _verify_bundle(self, bundle_der: bytes, tx_id: bytes) -> BundleVerifyOutcome:
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
                nonce_state = self._consume_nonce(
                    tx_id, stmt_oid, oid_instance, positional_instance
                )
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

            # 3. Submit to the verifier.
            verdict = self._submit(profile, nonce_state, stmt_oid, stmt_bytes, bundle_der)

            # 4. Optional reference-value check.
            if verdict.status == EarStatus.affirming and profile.reference_handler is not None:
                ref = profile.reference_handler.handle_evidence(stmt_bytes, attester_id=stmt_oid)
                if not ref.accepted:
                    logger.warning(
                        "RA engine: reference check rejected statement oid=%s: %s",
                        stmt_oid,
                        ref.reason,
                    )
                    verdict = VerifyResult.contraindicated(
                        f"reference check failed: {ref.reason or 'no reason given'}"
                    )

            verdicts.append(verdict)
            route_oids.append(stmt_oid)
            ear_jwts.append(verdict.payload if (verdict.accepted and isinstance(verdict.payload, str)) else None)

        result = BundleVerifyResult(per_statement=tuple(verdicts), routes=tuple(route_oids))
        return BundleVerifyOutcome(result=result, ear_jwts=tuple(ear_jwts))

    # ── Verifier submission ────────────────────────────────────────────────────

    def _submit(
        self,
        profile: AttestationProfile,
        nonce_state: NonceState,
        stmt_oid: str,
        stmt_bytes: bytes,
        bundle_der: bytes,
    ) -> VerifyResult:
        """Submit one statement to its profile's verifier and return the verdict.

        The default HTTP client (:class:`VeraisonVerifierClient`) is given the
        FULL ``AttestationBundle`` DER (the verifier decodes the bundle, selects
        the statement by ``evidence_oid`` and extracts the AK cert chain) plus
        the ``resp_info_json`` context; any other :class:`AttestationVerifier` is
        driven through the ABC ``verify_token`` with the unwrapped statement.
        """
        verifier: AttestationVerifier = profile.resolve_verifier()
        media_type = getattr(verifier, "media_type", "application/octet-stream")

        if isinstance(verifier, VeraisonVerifierClient):
            resp_info_json = self._resp_info_json(profile, nonce_state.resp_info)
            ear_jwt = verifier.submit_evidence(
                nonce=nonce_state.nonce,
                evidence=bundle_der,
                evidence_oid=stmt_oid,
                resp_info_json=resp_info_json,
            )
            if ear_jwt is None:
                return VerifyResult.contraindicated(
                    f"verifier rejected statement oid={stmt_oid}"
                )
            return VerifyResult.affirming(ear_jwt)

        return verifier.verify_token(stmt_bytes, media_type, nonce_state.nonce)

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

        The bundle's ``AttestationStatement.type`` always carries an OID, but the
        nonce-issue ``NonceRequest.type`` is optional: a typeless request files
        the nonce under ``(None, position)`` instead of ``(oid, instance)``.

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


class _NonceError(Exception):
    """Internal: any nonce-consume failure, mapped to an ``unknown`` verdict."""


__all__ = [
    "BundleVerifyOutcome",
    "RemoteAttestationEngine",
]
