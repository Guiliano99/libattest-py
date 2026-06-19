# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Per-OID attestation profile — the MockCA ``AttestationRoute`` moved into libattest.

An :class:`AttestationProfile` ties together everything the RA engine needs to
handle one attestation type end-to-end:

* the ``NonceRequest.type`` OID the client sends at nonce-issue time
  (``request_type_oid`` — e.g. ``TPM_PCR_SELECTION_OID``),
* the ``AttestationStatement.type`` OID the bundle carries
  (``statement_oid`` — e.g. ``TcgAttestQuote`` ``2.23.133.20.2``),
* the **format codecs** (``unwrap_statement``, ``parse_req_info``,
  ``build_resp_info``, ``resp_info_to_json``, ``encode_ear_extension``), and
* the two **pluggable services**: ``verifier`` (an
  :class:`~libattest.verifier.base.AttestationVerifier`) and
  ``reference_handler`` (a
  :class:`~libattest.verifier.reference.VerifierReferenceHandler`).

The verifier can be supplied directly (constructor injection of any ABC
implementation) **or** as a ``verifier_url`` consumed by the default
:class:`~libattest.ra.verifier_client.VeraisonVerifierClient`; :meth:`resolve_verifier`
returns whichever is configured (constructing and caching the default client on
first use).  Adding a new attestation type + its verifier is one
:func:`tpm_profile` / :func:`jwt_profile` call plus a registry ``register`` — no
engine edit.
"""

from __future__ import annotations

import functools
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field

from libattest.formats.csrattest import unwrap_attestation_statement
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.reference import VerifierReferenceHandler
from libattest.x509 import encode_ear_extension as _libattest_encode_ear_extension

logger = logging.getLogger(__name__)

# OID under which the EAR JWT is embedded as an X.509 extension on the issued
# cert.  Configurable via ``EAR_OID`` so a deployment can choose between the demo
# OID (default, raw-JWT extnValue) and the standard ``id-pe-cmw`` extension
# (CMW-wrapped extnValue).
DEFAULT_EAR_EXT_OID: str = os.environ.get("EAR_OID", "1.7.6.5.123")

# TCG TPM2 evidence-statement OIDs.
ID_TCG_ATTEST_QUOTE: str = "2.23.133.20.2"
ID_TCG_ATTEST_CERTIFY: str = "2.23.133.20.1"

# SHA-256 default bank for the TPM platform profile (the only algorithm the RA
# counter-proposes when the client's proposal is unsupported).
_DEFAULT_HASH_ALG_ID: int = 0x000B
_SUPPORTED_HASH_ALG_IDS: frozenset[int] = frozenset({_DEFAULT_HASH_ALG_ID})


def _negotiate_hash_alg_id(proposed: int | None) -> int:
    """Echo the client's proposed ``hashAlgId`` when supported, else SHA-256."""
    if proposed in _SUPPORTED_HASH_ALG_IDS:
        return proposed  # type: ignore[return-value]
    return _DEFAULT_HASH_ALG_ID


def _no_req_info(_req_info: bytes | None) -> int | None:
    """Default ``parse_req_info``: this type carries no negotiation params."""
    return None


def _default_encode_ear_extension(ear_oid: str) -> Callable[[str], tuple[str, bytes]]:
    """Bind libattest's ``encode_ear_extension`` to *ear_oid* for a profile.

    The returned callable maps an EAR JWT to ``(oid, extn_value_der)`` —
    CMW-wrapped when *ear_oid* is ``id-pe-cmw``, raw JWT bytes otherwise.
    """
    return functools.partial(_libattest_encode_ear_extension, oid=ear_oid)


@dataclass
class AttestationProfile:
    """Everything the RA engine needs to handle one attestation type.

    Attributes
    ----------
    request_type_oid:
        Dot-form ``NonceRequest.type`` OID (nonce-issue side).
    statement_oid:
        Dot-form ``AttestationStatement.type`` OID (evidence side).
    build_resp_info:
        ``(proposed_hash_alg_id) -> DER respInfo | None``.  Builds the DER
        ``NonceResponse.respInfo`` for this type from the client's proposed
        ``hashAlgId`` (``None`` when the type carries no respInfo).
    resp_info_to_json:
        ``(DER respInfo) -> dict``.  Serialises the DER respInfo to the JSON the
        engine forwards to the verifier.
    resp_info_label:
        Human-readable name of the respInfo payload type (operator logs only).
    parse_req_info:
        ``(reqInfo DER | None) -> hashAlgId int | None``.  Extracts the
        client-proposed ``hashAlgId`` from this type's ``NonceRequest.reqInfo``
        syntax.  Default: returns ``None`` (no negotiation).
    unwrap_statement:
        ``(stmt DER) -> (stmt_bytes, is_wrapped)``.  Unwraps the
        ``AttestationStatement.stmt`` open type.  Default: libattest's
        :func:`~libattest.formats.csrattest.unwrap_attestation_statement`.
    encode_ear_extension:
        ``(ear_jwt) -> (extn_oid_dot, extn_value_der)``.  Encodes the EAR JWT
        into the X.509 extension this profile embeds.  Default: libattest's
        ``encode_ear_extension`` bound to the env ``EAR_OID``.
    verifier:
        Concrete :class:`AttestationVerifier`, or ``None`` to build the default
        HTTP client from ``verifier_url``.
    verifier_url:
        Base URL for the default :class:`VeraisonVerifierClient` when
        ``verifier`` is ``None``.
    reference_handler:
        Optional :class:`VerifierReferenceHandler` consulted by the engine
        after a verifier verdict (``None`` to skip the reference check).

    """

    request_type_oid: str
    statement_oid: str
    build_resp_info: Callable[[int | None], bytes | None]
    resp_info_to_json: Callable[[bytes], dict]
    resp_info_label: str = "respInfo"
    parse_req_info: Callable[[bytes | None], int | None] = _no_req_info
    unwrap_statement: Callable[[bytes], tuple[bytes, bool]] = unwrap_attestation_statement
    encode_ear_extension: Callable[[str], tuple[str, bytes]] = field(
        default_factory=lambda: _default_encode_ear_extension(DEFAULT_EAR_EXT_OID)
    )
    verifier: AttestationVerifier | None = None
    verifier_url: str | None = None
    reference_handler: VerifierReferenceHandler | None = None

    def __post_init__(self) -> None:
        """Validate that a verifier is reachable (instance or URL)."""
        if self.verifier is None and not self.verifier_url:
            raise ValueError(
                f"AttestationProfile for statement={self.statement_oid} needs either "
                "a 'verifier' instance or a 'verifier_url'"
            )

    def resolve_verifier(self) -> AttestationVerifier:
        """Return the profile's verifier, building the default HTTP client lazily.

        When an explicit ``verifier`` was injected it is returned as-is.
        Otherwise a :class:`~libattest.ra.verifier_client.VeraisonVerifierClient`
        is constructed from ``verifier_url`` and cached on the profile so repeat
        submissions reuse one client (and its cached EAR key).
        """
        if self.verifier is None:
            # Lazy import keeps a verifier-instance profile free of the HTTP
            # client's requests/cryptography import cost.
            from libattest.ra.verifier_client import VeraisonVerifierClient  # noqa: PLC0415

            self.verifier = VeraisonVerifierClient(base_url=self.verifier_url)  # type: ignore[arg-type]
            logger.debug("AttestationProfile: built default verifier client for %s", self.verifier_url)
        return self.verifier


# ── Profile factories (small-registration ergonomics) ──────────────────────────


def tpm_profile(
    *,
    request_type_oid: str,
    statement_oid: str,
    verifier: AttestationVerifier | None = None,
    verifier_url: str | None = None,
    reference_handler: VerifierReferenceHandler | None = None,
    pcrs: list[int] | None = None,
    resp_info_label: str = "TpmAttestationParams",
    ear_oid: str = DEFAULT_EAR_EXT_OID,
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for a TPM ``TpmAttestationParams`` type.

    Mirrors the MockCA ``tpm_route`` factory.  The profile:

    * parses the client's proposed ``hashAlgId`` from a ``TpmAttestationParams``
      reqInfo,
    * when *pcrs* is given, broadcasts a ``TpmAttestationParams`` respInfo
      carrying that PCR set + the negotiated hash algorithm (the quote leg);
      when *pcrs* is ``None`` no respInfo is built (the certify leg),
    * serialises that respInfo DER → JSON via the libattest respInfo registry,
    * uses the libattest defaults for statement unwrap + EAR encoding.

    TPM-format imports are deferred to call time so importing
    :mod:`libattest.ra` never pulls the TPM format stack.
    """
    # Lazy: the TPM format package eagerly imports native bindings on some hosts.
    from libattest.formats.respinfo import DEFAULT_RESP_INFO_REGISTRY  # noqa: PLC0415
    from libattest.formats.tpm import (  # noqa: PLC0415
        decode_tpm_attestation_params,
        make_pcr_selection_resp_info,
    )

    def parse_req_info(req_info: bytes | None) -> int | None:
        if not req_info:
            return None
        try:
            _pcrs, hash_alg_id = decode_tpm_attestation_params(bytes(req_info))
        except ValueError:
            return None
        return hash_alg_id

    if pcrs is not None:
        pcrs_list = list(pcrs)

        def build_resp_info(proposed: int | None) -> bytes | None:
            return bytes(make_pcr_selection_resp_info(pcrs_list, _negotiate_hash_alg_id(proposed)))
    else:

        def build_resp_info(_proposed: int | None) -> bytes | None:
            return None

    return AttestationProfile(
        request_type_oid=request_type_oid,
        statement_oid=statement_oid,
        build_resp_info=build_resp_info,
        resp_info_to_json=lambda der, oid=statement_oid: DEFAULT_RESP_INFO_REGISTRY.to_json(oid, der),
        resp_info_label=resp_info_label,
        parse_req_info=parse_req_info,
        encode_ear_extension=_default_encode_ear_extension(ear_oid),
        verifier=verifier,
        verifier_url=verifier_url,
        reference_handler=reference_handler,
    )


def jwt_profile(
    *,
    request_type_oid: str,
    statement_oid: str,
    verifier: AttestationVerifier | None = None,
    verifier_url: str | None = None,
    reference_handler: VerifierReferenceHandler | None = None,
    ear_oid: str = DEFAULT_EAR_EXT_OID,
    resp_info_label: str = "respInfo",
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for opaque-JWT evidence.

    Mirrors the MockCA ``jwt_route`` factory: a URL/verifier-only profile with
    no respInfo and no reqInfo negotiation.  The evidence ``stmt`` is an OCTET
    STRING (the libattest default unwrap strips it), and the EAR JWT is embedded
    under *ear_oid* (raw bytes, or CMW-wrapped when *ear_oid* is ``id-pe-cmw``).
    """
    return AttestationProfile(
        request_type_oid=request_type_oid,
        statement_oid=statement_oid,
        build_resp_info=lambda _proposed: None,
        resp_info_to_json=lambda der: {},
        resp_info_label=resp_info_label,
        encode_ear_extension=_default_encode_ear_extension(ear_oid),
        verifier=verifier,
        verifier_url=verifier_url,
        reference_handler=reference_handler,
    )


__all__ = [
    "DEFAULT_EAR_EXT_OID",
    "ID_TCG_ATTEST_CERTIFY",
    "ID_TCG_ATTEST_QUOTE",
    "AttestationProfile",
    "jwt_profile",
    "tpm_profile",
]
