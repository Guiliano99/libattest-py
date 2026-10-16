# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""What the attester is willing to tell a particular verifier.

Encrypting Evidence to one verifier keeps it from everyone else — it does nothing about
what that verifier itself learns.  An EAT claim set is device-identifying by
construction (``ueid``, boot state, firmware measurements, hardware model), and the
attester currently hands the whole set to whichever verifier the RA happened to name.
Confidentiality on the wire without a decision about the recipient is only half of a
privacy story: the remaining question is *which* claims this verifier gets to see.

:class:`ClaimReleasePolicy` is that decision, made once at the attester and applied
before anything is signed — not after, because a claim that has been signed into an EAT
has already left, whatever the transport does with it afterwards.

The default is deliberately **release everything**: a policy that silently dropped
claims would break existing attesters and, worse, produce Evidence that fails appraisal
for reasons no log explains.  Withholding is something a deployment opts into, and every
withheld claim is logged.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: Claims every verifier needs regardless of policy: without them the Evidence is not
#: appraisable at all, so withholding one is a configuration error rather than a
#: privacy choice.  ``eat_nonce`` is the freshness binding; ``eat_profile`` names the
#: claim set's own semantics.
ESSENTIAL_CLAIMS: frozenset[str] = frozenset({"eat_nonce", "eat_profile"})


def _as_frozenset(names: Iterable[str] | str | None) -> frozenset[str]:
    """Coerce a claim-name declaration to a set, treating a bare ``str`` as one name."""
    if names is None:
        return frozenset()
    if isinstance(names, str):
        return frozenset({names})
    return frozenset(names)


@dataclass(frozen=True)
class ClaimReleasePolicy:
    """Filter an EAT claim set down to what one verifier is allowed to see.

    Attributes
    ----------
    allow:
        When set, **only** these claims (plus :data:`ESSENTIAL_CLAIMS`) are released.
        ``None`` means "no allow-list": everything not denied is released.
    deny:
        Claims never released, applied after *allow*.  A claim in both is denied —
        the more restrictive rule wins, so a policy can never be widened by accident.
    per_verifier:
        Per-verifier allow-lists keyed by the RA's configured verifier id, overriding
        :attr:`allow` for that verifier.  This is the useful shape in practice: a
        platform verifier needs the firmware measurements, a key-attestation verifier
        does not, and neither needs the other's claims.

    """

    allow: Iterable[str] | str | None = None
    deny: Iterable[str] | str = frozenset()
    per_verifier: Mapping[str, Iterable[str] | str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Normalise the claim-name declarations, treating a bare ``str`` as one name.

        ``deny="ueid"`` would otherwise deny the letters ``u``, ``e``, ``i`` and ``d``
        and release the claim itself — a privacy control that silently does nothing is
        worse than no control, so the coercion happens once, here.
        """
        object.__setattr__(self, "allow", None if self.allow is None else _as_frozenset(self.allow))
        object.__setattr__(self, "deny", _as_frozenset(self.deny))
        object.__setattr__(
            self,
            "per_verifier",
            {name: _as_frozenset(claims) for name, claims in self.per_verifier.items()},
        )

    @classmethod
    def release_all(cls) -> ClaimReleasePolicy:
        """Return the permissive default: every claim goes to every verifier."""
        return cls()

    def allowed_for(self, verifier_id: str | None) -> frozenset[str] | None:
        """Return the effective allow-list for *verifier_id*, or ``None`` for no limit."""
        if verifier_id is not None and verifier_id in self.per_verifier:
            return _as_frozenset(self.per_verifier[verifier_id])
        return None if self.allow is None else _as_frozenset(self.allow)

    def release(self, claims: Mapping[str, Any], *, verifier_id: str | None = None) -> dict[str, Any]:
        """Return the subset of *claims* this policy releases to *verifier_id*.

        Claim **order is preserved**, because a claim set is serialised in iteration
        order and a reordered EAT is a different byte string to anything that has
        already measured or cached one.
        """
        allow = self.allowed_for(verifier_id)
        released: dict[str, Any] = {}
        withheld: list[str] = []
        for name, value in claims.items():
            if self._releases(name, allow):
                released[name] = value
            else:
                withheld.append(name)
        if withheld:
            logger.info(
                "attester: withholding %d claim(s) from verifier %s: %s",
                len(withheld),
                verifier_id or "<unnamed>",
                ", ".join(sorted(withheld)),
            )
        return released

    def _releases(self, name: str, allow: frozenset[str] | None) -> bool:
        """Return whether one claim survives this policy."""
        if name in ESSENTIAL_CLAIMS:
            return True
        if name in _as_frozenset(self.deny):
            return False
        return allow is None or name in allow


def release_claims(
    claims: Mapping[str, Any],
    policy: ClaimReleasePolicy | None,
    *,
    verifier_id: str | None = None,
) -> dict[str, Any]:
    """Apply *policy* to *claims*, or return them unchanged when no policy is configured.

    The convenience form for a call site that may or may not have been given a policy,
    so "no policy" does not have to be spelled out at every seal.
    """
    if policy is None:
        return dict(claims)
    return policy.release(claims, verifier_id=verifier_id)


__all__ = [
    "ESSENTIAL_CLAIMS",
    "ClaimReleasePolicy",
    "release_claims",
]
