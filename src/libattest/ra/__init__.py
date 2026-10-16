# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Protocol-agnostic Remote Attestation engine.

``libattest.ra`` is the reusable RA orchestration the MockCA used to own:
nonce lifecycle, bundle → verify → EAR aggregation, the default HTTP verifier
client, and the per-OID profile + service registries.  The interface is
bytes / OID-strings / verdict objects — never a ``PKIMessage`` — so any carrier
(CMP, REST, …) can drive it.

Two replaceable seams are first-class (reusing the existing libattest ABCs):

* swap the **verifier** — implement the RA-owned
  :class:`~libattest.ra.ports.EvidenceVerifier` port (or the older
  :class:`~libattest.verifier.base.AttestationVerifier` ABC, adapted automatically)
  and register it via :class:`ServiceRegistry`, or inject one on an
  :class:`AttestationProfile`;
* swap the **reference-value** service — register a custom
  :class:`~libattest.verifier.reference.VerifierReferenceHandler` the same way.

Neither swap touches the engine or profile code.
"""

from libattest.ra.engine import BundleVerifyOutcome, RemoteAttestationEngine
from libattest.ra.nonce import (
    DEFAULT_NONCE_BYTES,
    DEFAULT_TTL_SECONDS,
    BadNonceRequest,
    NonceState,
    NonceStore,
    ReplayError,
)
from libattest.ra.ports import (
    AppraisalRequest,
    EvidenceVerifier,
    LegacyVerifierPort,
    as_evidence_verifier,
)
from libattest.ra.profile import (
    AttestationProfile,
    VerifierProvisioning,
    hpke_profile,
    jwt_profile,
    key_attest_profile,
    se05x_profile,
    tpm_profile,
)
from libattest.ra.registry import ProfileRegistry, ServiceRegistry
from libattest.ra.relying_party import (
    EarAcceptancePolicy,
    EarDecision,
    TrustAnchor,
    load_trust_anchor,
)
from libattest.ra.verifier_client import VeraisonVerifierClient

__all__ = [
    "DEFAULT_NONCE_BYTES",
    "DEFAULT_TTL_SECONDS",
    "AppraisalRequest",
    "AttestationProfile",
    "BadNonceRequest",
    "BundleVerifyOutcome",
    "EarAcceptancePolicy",
    "EarDecision",
    "EvidenceVerifier",
    "LegacyVerifierPort",
    "NonceState",
    "NonceStore",
    "ProfileRegistry",
    "RemoteAttestationEngine",
    "ReplayError",
    "ServiceRegistry",
    "TrustAnchor",
    "VerifierProvisioning",
    "VeraisonVerifierClient",
    "as_evidence_verifier",
    "load_trust_anchor",
    "hpke_profile",
    "jwt_profile",
    "key_attest_profile",
    "se05x_profile",
    "tpm_profile",
]
