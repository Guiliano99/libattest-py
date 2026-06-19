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

* swap the **verifier** — register a custom
  :class:`~libattest.verifier.base.AttestationVerifier` via
  :class:`ServiceRegistry`, or inject one on an :class:`AttestationProfile`;
* swap the **reference-value** service — register a custom
  :class:`~libattest.verifier.reference.VerifierReferenceHandler` the same way.

Neither swap touches the engine or profile code.
"""

from libattest.ra.engine import BundleVerifyOutcome, RemoteAttestationEngine
from libattest.ra.nonce import (
    DEFAULT_NONCE_BYTES,
    DEFAULT_TTL_SECONDS,
    NonceState,
    NonceStore,
    ReplayError,
)
from libattest.ra.profile import (
    DEFAULT_EAR_EXT_OID,
    ID_TCG_ATTEST_CERTIFY,
    ID_TCG_ATTEST_QUOTE,
    AttestationProfile,
    jwt_profile,
    tpm_profile,
)
from libattest.ra.registry import ProfileRegistry, ServiceRegistry
from libattest.ra.verifier_client import VeraisonVerifierClient

__all__ = [
    "DEFAULT_EAR_EXT_OID",
    "DEFAULT_NONCE_BYTES",
    "DEFAULT_TTL_SECONDS",
    "ID_TCG_ATTEST_CERTIFY",
    "ID_TCG_ATTEST_QUOTE",
    "AttestationProfile",
    "BundleVerifyOutcome",
    "NonceState",
    "NonceStore",
    "ProfileRegistry",
    "RemoteAttestationEngine",
    "ReplayError",
    "ServiceRegistry",
    "VeraisonVerifierClient",
    "jwt_profile",
    "tpm_profile",
]
