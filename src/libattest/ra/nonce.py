# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Protocol-agnostic RA nonce store.

This is the reusable core extracted from the MockCA ``nonce_handler``: it owns
nonce generation, per-transaction storage keyed by ``(tx_id, statement-OID,
instance)``, one-shot consumption with replay/expiry detection, and the
``respInfo`` lifecycle (the DER ``NonceResponse.respTypeInfo.respInfo`` the RA
broadcast for a slot, stored alongside the nonce for the verifier hop).

All CMP specifics are dropped: keys are ``bytes`` transaction identifiers and
dot-form OID strings (never a ``PKIMessage``), and verifier-URL resolution is
**not** baked in here — the engine resolves a profile and reads
``profile.verifier`` instead.  This keeps the store usable by any transport.

Consolidation note
------------------
This is the single RA nonce store for the engine.  ``verifier/router.py`` keeps
a separate nonce→route map (``_NonceEntry``) used by the simpler
``VerifierRouter.verify_bundle`` flow; that is a different, lower-level concept
(nonce *value* → route, no per-transaction lifecycle).  The
:class:`RemoteAttestationEngine` uses **this** store exclusively and does not
also stand up a ``VerifierRouter`` nonce map, so there is exactly one nonce
lifecycle per engine.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)

DEFAULT_TTL_SECONDS = 300
DEFAULT_NONCE_BYTES = 32


class ReplayError(Exception):
    """Raised when a ``(tx_id, oid, instance)`` slot is consumed a second time."""


class BadNonceRequest(Exception):
    """Raised when an incoming ``NonceRequest`` violates the freshness protocol.

    Generic RA-protocol validation (e.g. a requested nonce length below the
    configured minimum). Carriers map this to their own error type — the CMP
    MockCA re-raises it as ``resources.exceptions.BadNonceRequest`` so the
    outer CMP layer returns the correct PKIStatus.
    """


@dataclass
class NonceState:
    """One RA-issued nonce with its lifecycle and routing metadata.

    Attributes
    ----------
    nonce:
        Plaintext attestation nonce ``N`` (always wire-side plaintext); used by
        the attester as ``TPM2_Quote.qualifyingData`` for the TPM profile.
    tx_id:
        Transaction identifier the nonce was issued under.
    statement_oid:
        Dot-form OID of the evidence statement this nonce gates, or ``None``
        when the request carried no type (positional addressing).
    instance:
        0-based per-OID instance index within the transaction (multi-attester).
    created_at / expires_at:
        ``time.monotonic()`` issuance time and TTL deadline.
    consumed / consumed_at:
        One-shot consumption flag and timestamp.
    resp_info:
        DER of the type-specific ``NonceResponse.respTypeInfo.respInfo`` for
        this slot (e.g. ``TPM20QuoteRespInfo``), or ``None`` when the type
        carries no respInfo.  Stored so the engine can forward it to the
        verifier.
    session_id:
        Verifier session identifier bound to this nonce, set only for the
        key-attestation (credential-activation) profile: the verifier issues it
        alongside the MakeCredential blobs, the RA binds ``tx_id → session_id``
        here, and ``verify_bundle`` echoes it back so the verifier can find the
        retained seed.  ``None`` for every other profile.

    """

    nonce: bytes
    tx_id: bytes
    statement_oid: str | None
    instance: int
    created_at: float
    expires_at: float
    consumed: bool = False
    consumed_at: float | None = None
    resp_info: bytes | None = None
    session_id: str | None = None


@dataclass
class _TxState:
    """All nonce slots belonging to a single transaction."""

    nonces: dict[tuple[str | None, int], NonceState] = field(default_factory=dict)
    expires_at: float = 0.0


class NonceStore:
    """Per-transaction RA nonce generator with one-shot consumption.

    Parameters
    ----------
    ttl_seconds:
        Lifetime of a nonce / transaction before eviction.  Falls back to the
        ``NONCE_TTL_SECONDS`` env var, then :data:`DEFAULT_TTL_SECONDS`.
    nonce_bytes:
        Length of each generated nonce.  Defaults to :data:`DEFAULT_NONCE_BYTES`.

    Notes
    -----
    Holds an internal :class:`~threading.Lock` so a multi-worker deployment
    does not race; single-threaded request flows pay only an uncontended lock.

    """

    def __init__(
        self,
        ttl_seconds: int | None = None,
        nonce_bytes: int | None = None,
    ) -> None:
        """Initialise an empty store with the given TTL and nonce size."""
        self._tx: dict[bytes, _TxState] = {}
        self._lock = Lock()
        self._ttl = int(
            ttl_seconds if ttl_seconds is not None else os.environ.get("NONCE_TTL_SECONDS", DEFAULT_TTL_SECONDS)
        )
        self._nonce_bytes = int(nonce_bytes or DEFAULT_NONCE_BYTES)

    # ── Issuance ──────────────────────────────────────────────────────────────

    def issue(
        self,
        tx_id: bytes,
        statement_oid: str | None,
        *,
        resp_info: bytes | None = None,
        session_id: str | None = None,
    ) -> NonceState:
        """Generate and store a fresh nonce for ``(tx_id, statement_oid)``.

        Auto-increments the per-OID instance index: two ``issue()`` calls with
        the same ``(tx_id, statement_oid)`` return ``instance=0`` then
        ``instance=1`` (multi-attester support).

        Parameters
        ----------
        tx_id:
            Transaction identifier; the nonce is stored and later consumed
            under this id.
        statement_oid:
            Dot-form evidence-statement OID the nonce gates, or ``None`` for a
            positionally-addressed slot.
        resp_info:
            Optional DER ``NonceResponse.respTypeInfo.respInfo`` to remember
            for this slot.
        session_id:
            Optional verifier session id to bind to this nonce (key-attestation
            profile only); echoed back at ``verify_bundle`` time.

        Returns
        -------
        NonceState
            The stored state, including the generated ``nonce``.

        """
        with self._lock:
            self._evict_expired_locked()
            tx = self._tx.setdefault(tx_id, _TxState())
            if tx.expires_at == 0.0:
                tx.expires_at = time.monotonic() + self._ttl

            existing = [inst for (oid, inst) in tx.nonces if oid == statement_oid]
            instance = (max(existing) + 1) if existing else 0

            now = time.monotonic()
            state = NonceState(
                nonce=os.urandom(self._nonce_bytes),
                tx_id=tx_id,
                statement_oid=statement_oid,
                instance=instance,
                created_at=now,
                expires_at=now + self._ttl,
                resp_info=resp_info,
                session_id=session_id,
            )
            tx.nonces[(statement_oid, instance)] = state
            logger.info(
                "NonceStore.issue tx=%s oid=%s inst=%d N=%dB%s",
                tx_id.hex(),
                statement_oid or "<none>",
                instance,
                len(state.nonce),
                f" respInfo={len(resp_info)}B" if resp_info else "",
            )
            return state

    # ── Consumption ───────────────────────────────────────────────────────────

    def consume(
        self,
        tx_id: bytes,
        statement_oid: str | None,
        instance: int,
    ) -> NonceState:
        """Return the nonce for the slot and mark it consumed (one-shot).

        Parameters
        ----------
        tx_id:
            Transaction identifier the nonce was issued under.
        statement_oid:
            Dot-form OID (or ``None``) the nonce was filed under.
        instance:
            Per-OID instance index.

        Raises
        ------
        KeyError
            No nonce was issued for that ``(tx_id, oid, instance)`` triple.
        ValueError
            The nonce expired (the slot is dropped).
        ReplayError
            The slot was already consumed in this transaction.

        """
        with self._lock:
            self._evict_expired_locked()
            tx = self._tx.get(tx_id)
            if tx is None:
                raise KeyError(f"no nonces issued for tx_id={tx_id.hex()} (transaction unknown or already cleaned up)")
            state = tx.nonces.get((statement_oid, instance))
            if state is None:
                raise KeyError(f"no nonce for (tx={tx_id.hex()}, oid={statement_oid or '<none>'}, instance={instance})")
            now = time.monotonic()
            if now > state.expires_at:
                del tx.nonces[(statement_oid, instance)]
                raise ValueError(f"nonce expired (TTL={self._ttl}s) for tx={tx_id.hex()}")
            if state.consumed:
                raise ReplayError(f"nonce already consumed at t={state.consumed_at} for tx={tx_id.hex()}")
            state.consumed = True
            state.consumed_at = now
            logger.info(
                "NonceStore.consume tx=%s oid=%s inst=%d",
                tx_id.hex(),
                statement_oid or "<none>",
                instance,
            )
            return state

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def drop_transaction(self, tx_id: bytes) -> None:
        """Forget every nonce associated with *tx_id* (eager cleanup)."""
        with self._lock:
            self._tx.pop(tx_id, None)

    def stats(self) -> dict:
        """Diagnostic snapshot — counts only, no nonce material."""
        with self._lock:
            return {
                "transactions": len(self._tx),
                "total_nonces": sum(len(t.nonces) for t in self._tx.values()),
                "consumed_nonces": sum(1 for t in self._tx.values() for n in t.nonces.values() if n.consumed),
            }

    # ── Internals ─────────────────────────────────────────────────────────────

    def _evict_expired_locked(self) -> None:
        """Drop transactions whose TTL window has elapsed (caller holds lock)."""
        now = time.monotonic()
        expired = [tid for tid, tx in self._tx.items() if tx.expires_at and now > tx.expires_at]
        for tid in expired:
            count = len(self._tx[tid].nonces)
            del self._tx[tid]
            logger.info(
                "NonceStore evicted expired transaction tx=%s (%d nonce(s))",
                tid.hex(),
                count,
            )


__all__ = [
    "DEFAULT_NONCE_BYTES",
    "DEFAULT_TTL_SECONDS",
    "BadNonceRequest",
    "NonceState",
    "NonceStore",
    "ReplayError",
]
