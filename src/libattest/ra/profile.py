# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Per-OID attestation profile — the MockCA ``AttestationRoute`` moved into libattest.

An :class:`AttestationProfile` ties together everything the RA engine needs to
handle one attestation type end-to-end:

* the ``NonceRequest.reqTypeInfo.type`` OID the client sends at nonce-issue time
  (``request_type_oid`` — e.g. ``get_nonce_request_oid_for_name("tpm-quote")``),
* the ``AttestationStatement.type`` OID the bundle carries
  (``statement_oid`` — e.g. the ``"tcg-attest-quote"`` OID exposed by
  :func:`libattest.get_oid_by_name`, carried as a ``TcgAttestCertify`` value),
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
from typing import TYPE_CHECKING

from libattest import (
    get_nonce_request_oid_for_name,
    get_nonce_response_oid_for_name,
    get_oid_by_name,
    get_oid_for_stmt_name,
)
from libattest.formats.csrattest import unwrap_attestation_statement
from libattest.ra.relying_party import TrustAnchor
from libattest.verifier.base import AttestationVerifier
from libattest.verifier.reference import VerifierReferenceHandler
from libattest.x509 import encode_ear_extension as _libattest_encode_ear_extension

if TYPE_CHECKING:
    from libattest.verifier.se05x import Se05xAttestVerifier

logger = logging.getLogger(__name__)

# SHA-256 default bank for the TPM platform profile (the only algorithm the RA
# counter-proposes when the client's proposal is unsupported).
_DEFAULT_HASH_ALG_ID: int = 0x000B
_SUPPORTED_HASH_ALG_IDS: frozenset[int] = frozenset({_DEFAULT_HASH_ALG_ID})


def _negotiate_hash_alg_id(proposed: int | None) -> int:
    if proposed is not None and proposed in _SUPPORTED_HASH_ALG_IDS:
        return proposed
    return _DEFAULT_HASH_ALG_ID


def _no_req_info(_req_info: bytes | None) -> int | None:
    """Default ``parse_req_info``: this type carries no negotiation params."""
    return None


def _cmw_is_the_statement(stmt_der: bytes) -> tuple[bytes, bool]:
    """``unwrap_statement`` for a profile whose ``stmt`` is already the payload.

    The generic
    :func:`~libattest.formats.csrattest.unwrap_attestation_statement` strips a
    leading ``OCTET STRING`` wrapper, which is right for opaque evidence and **wrong**
    for a CMW record: the CBOR flavour of a CMW *is* an ``OCTET STRING`` at top level,
    so the generic unwrap eats the CMW itself and hands the verifier bare CBOR.  A COSE
    CMW statement therefore cannot survive the default unwrap at all.
    """
    return stmt_der, False


def _default_encode_ear_extension(ear_oid: str) -> Callable[[str], tuple[str, bytes]]:
    """Bind libattest's ``encode_ear_extension`` to *ear_oid* for a profile.

    The returned callable maps an EAR JWT to ``(oid, extn_value_der)`` —
    CMW-wrapped when *ear_oid* is ``id-pe-cmw``, otherwise DER-encoded using
    the EAR extension's UTF8String syntax.
    """
    return functools.partial(_libattest_encode_ear_extension, oid=ear_oid)


def _default_ear_extension_oid() -> str:
    """Return the configured EAR extension OID or the centrally registered demo default."""
    value = os.environ.get("EAR_OID")
    if value is not None and value.strip():
        return value.strip()
    return get_oid_by_name("demo-ear-extension")


def _effective_ear_extension_oid(ear_oid: str | None) -> str:
    """Return an explicit profile OID or resolve the current ``EAR_OID`` value."""
    return _default_ear_extension_oid() if ear_oid is None else ear_oid


@dataclass(frozen=True)
class VerifierProvisioning:
    """What one profile provisions into a ``NonceResponse`` for one exchange.

    Attributes
    ----------
    resp_info:
        DER for ``NonceResponse.respTypeInfo.respInfo``, or ``None`` when the profile
        negotiates nothing.  Its syntax is selected by the profile's
        ``response_type_oid``.
    session_id:
        Verifier session id to bind to the nonce, for a profile whose provisioning came
        from a verifier round-trip (the key-attestation MakeCredential leg).
    label:
        Human-readable name of the respInfo syntax, for logs.

    """

    resp_info: bytes | None = None
    session_id: str | None = None
    label: str = "respInfo"


@dataclass
class AttestationProfile:
    """Everything the RA engine needs to handle one attestation type.

    Attributes
    ----------
    request_type_oid:
        Dot-form ``NonceRequest.reqTypeInfo.type`` OID (nonce-issue side).
    response_type_oid:
        Dot-form ``NonceResponse.respTypeInfo.type`` OID (nonce-answer side).
        Request and response are distinct wire positions, so a profile may use a
        different OID in each (the TPM quote profile does).  Defaults to
        ``request_type_oid`` — the same-OID case used by the jwt and
        key-attestation profiles, where the position alone selects the syntax.
        Never derive Evidence selection from this value (see UPDATE.md).
    statement_oid:
        Dot-form ``AttestationStatement.type`` OID (evidence side).
    build_resp_info:
        ``(proposed_hash_alg_id) -> DER respInfo | None``.  Builds the DER
        ``NonceResponseTypeInfo.respInfo`` for this type from the client's
        proposed hash algorithm (``None`` when the type carries no respInfo).
    resp_info_to_json:
        ``(DER respInfo) -> dict``.  Serialises the DER respInfo to the JSON the
        engine forwards to the verifier.
    resp_info_label:
        Human-readable name of the respInfo payload type (operator logs only).
    parse_req_info:
        ``(reqInfo DER | None) -> hashAlgId int | None``.  Extracts a
        client-supported hash algorithm from this type's
        ``NonceRequestTypeInfo.reqInfo`` syntax.  Default: returns ``None``.
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
    build_challenge:
        Optional ``(reqInfo DER | None, verifier) -> (respInfo DER | None,
        session_id | None)``.  When set, :meth:`RemoteAttestationEngine.issue_nonce`
        calls this **instead of** ``parse_req_info`` / ``build_resp_info`` to
        produce the respInfo via a verifier round-trip (the key-attestation
        MakeCredential leg) and bind the returned session id to the nonce.
        ``None`` for stateless profiles (quote / jwt).
    binds_subject_key:
        Whether this profile's verifier must be handed the to-be-certified
        ``SubjectPublicKeyInfo`` so it can bind the attested key to the CSR key.  Set
        by :func:`key_attest_profile`.  Previously the engine inferred this from
        ``build_challenge is not None`` — two unrelated properties (needing a verifier
        round-trip at nonce time, and needing the CSR key at evidence time) that only
        happen to coincide in the one shipped profile.  Profiles that do not declare it
        are never handed the subject key.
    verifier_id:
        The deployment's name for this profile's verifier, as it appears in the
        ``ear.verifier-id.developer`` claim of the EARs it issues.  Configured here, it
        selects the EAR trust anchor out of a policy-wide anchor map **without reading
        an unverified claim out of the token first**.
    media_type:
        The IANA media type of this profile's Evidence.  The RA cannot learn it from the
        wire — an ``AttestationStatement`` carries a type OID, not a media type — so a
        deployment declares it here; without it the RA falls back to echoing whatever
        the verifier object says it accepts.
    ear_anchor:
        Optional pinned EAR verification key for *this* profile's verifier, used by
        the engine's :class:`~libattest.ra.relying_party.EarAcceptancePolicy` in
        preference to the policy-wide anchors.  Pinning per profile is the stronger
        configuration: it never has to select an anchor by reading an unverified
        claim out of the EAR itself.

    """

    request_type_oid: str
    statement_oid: str
    build_resp_info: Callable[[int | None], bytes | None]
    resp_info_to_json: Callable[[bytes], dict]
    response_type_oid: str | None = None  # None -> same OID as the request (see __post_init__)
    resp_info_label: str = "respInfo"
    parse_req_info: Callable[[bytes | None], int | None] = _no_req_info
    unwrap_statement: Callable[[bytes], tuple[bytes, bool]] = unwrap_attestation_statement
    encode_ear_extension: Callable[[str], tuple[str, bytes]] = field(
        default_factory=lambda: _default_encode_ear_extension(_default_ear_extension_oid())
    )
    verifier: AttestationVerifier | None = None
    verifier_url: str | None = None
    reference_handler: VerifierReferenceHandler | None = None
    build_challenge: Callable[[bytes | None, AttestationVerifier], tuple[bytes | None, str | None]] | None = None
    binds_subject_key: bool = False
    verifier_id: str | None = None
    media_type: str | None = None
    ear_anchor: TrustAnchor | None = None

    def __post_init__(self) -> None:
        """Default the response OID to the request's, and validate the verifier."""
        # Same-OID profiles (jwt, key-attest) answer under the request's OID; the
        # wire position still selects the syntax. Profiles whose response OID
        # differs (TPM quote) pass it explicitly.
        if self.response_type_oid is None:
            self.response_type_oid = self.request_type_oid
        if self.verifier is None and not self.verifier_url:
            raise ValueError(
                f"AttestationProfile for statement={self.statement_oid} needs either "
                "a 'verifier' instance or a 'verifier_url'"
            )

    def build_verifier_info(self, req_info: bytes | None) -> VerifierProvisioning:
        """Produce the verifier information the RA hands the attester for this exchange.

        The engine used to branch on ``build_challenge is not None`` and run two
        different shapes of code — parse-then-build for a stateless profile, a verifier
        round-trip for a challenge one — which meant "what does the RA tell the attester
        about the verifier" had no single answer to point at.  Both shapes now answer
        one question and return one :class:`VerifierProvisioning`.
        """
        if self.build_challenge is not None:
            resp_info, session_id = self.build_challenge(req_info, self.resolve_verifier())
            return VerifierProvisioning(resp_info=resp_info, session_id=session_id, label=self.resp_info_label)
        resp_info = self.build_resp_info(self.parse_req_info(req_info))
        return VerifierProvisioning(resp_info=resp_info, label=self.resp_info_label)

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
    certificate_name: str | None = None,
    resp_info_label: str = "TPM20QuoteRespInfo",
    ear_oid: str | None = None,
    ear_anchor: TrustAnchor | None = None,
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for the TPM 2.0 quote profile.

    Mirrors the MockCA ``tpm_route`` factory.  The profile:

    * parses the client's ``supportedHashAlgo`` values from ``TPM20QuoteReqInfo``,
    * when *pcrs* is given, broadcasts a ``TPM20QuoteRespInfo`` respInfo carrying
      that PCR set + the negotiated hash algorithm (the quote leg); when *pcrs*
      is ``None`` no respInfo is built (the certify leg),
    * serialises that respInfo DER → JSON via the libattest respInfo registry,
    * uses the libattest defaults for statement unwrap + EAR encoding.

    TPM-format imports are deferred to call time so importing
    :mod:`libattest.ra` never pulls the TPM format stack.
    """
    # Lazy: the TPM format package eagerly imports native bindings on some hosts.
    from libattest.formats.respinfo import DEFAULT_RESP_INFO_REGISTRY  # noqa: PLC0415
    from libattest.formats.tpm import (  # noqa: PLC0415
        decode_tpm20_quote_req_info,
        tpm20_quote_response_info,
    )

    def parse_req_info(req_info: bytes | None) -> int | None:
        if not req_info:
            return None
        try:
            _certificate_names, supported_hash_algos = decode_tpm20_quote_req_info(bytes(req_info))
        except ValueError:
            return None
        if supported_hash_algos is None:
            return None
        for hash_alg_id in supported_hash_algos:
            if hash_alg_id in _SUPPORTED_HASH_ALG_IDS:
                return hash_alg_id
        return None

    if pcrs is not None:
        pcrs_list = list(pcrs)

        def build_tpm20_quote_resp_info(proposed: int | None) -> bytes | None:
            return bytes(
                tpm20_quote_response_info(
                    certificate_name=certificate_name,
                    pcr_selection=pcrs_list,
                    hash_algo=_negotiate_hash_alg_id(proposed),
                )
            )

        selected_build_resp_info = build_tpm20_quote_resp_info
    else:

        def no_resp_info(_proposed: int | None) -> bytes | None:
            return None

        selected_build_resp_info = no_resp_info

    return AttestationProfile(
        request_type_oid=request_type_oid,
        # The quote profile answers under a DIFFERENT OID than it was asked
        # under; respTypeInfo.type selects the TPM20QuoteRespInfo syntax.
        response_type_oid=get_nonce_response_oid_for_name("tpm-quote"),
        statement_oid=statement_oid,
        build_resp_info=selected_build_resp_info,
        resp_info_to_json=lambda der: DEFAULT_RESP_INFO_REGISTRY.to_json(
            get_nonce_response_oid_for_name("tpm-quote"), der
        ),
        resp_info_label=resp_info_label,
        parse_req_info=parse_req_info,
        encode_ear_extension=_default_encode_ear_extension(_effective_ear_extension_oid(ear_oid)),
        verifier=verifier,
        verifier_url=verifier_url,
        reference_handler=reference_handler,
        ear_anchor=ear_anchor,
    )


def jwt_profile(
    *,
    request_type_oid: str,
    statement_oid: str,
    verifier: AttestationVerifier | None = None,
    verifier_url: str | None = None,
    reference_handler: VerifierReferenceHandler | None = None,
    ear_oid: str | None = None,
    resp_info_label: str = "respInfo",
    ear_anchor: TrustAnchor | None = None,
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for opaque-JWT evidence.

    Mirrors the MockCA ``jwt_route`` factory: a URL/verifier-only profile with
    no respInfo and no reqInfo negotiation.  The evidence ``stmt`` is an OCTET
    STRING (the libattest default unwrap strips it), and the EAR JWT is embedded
    under *ear_oid* (UTF8String DER, or CMW-wrapped when *ear_oid* is
    ``id-pe-cmw``).
    """
    return AttestationProfile(
        request_type_oid=request_type_oid,
        statement_oid=statement_oid,
        build_resp_info=lambda _proposed: None,
        resp_info_to_json=lambda der: {},
        resp_info_label=resp_info_label,
        encode_ear_extension=_default_encode_ear_extension(_effective_ear_extension_oid(ear_oid)),
        verifier=verifier,
        verifier_url=verifier_url,
        reference_handler=reference_handler,
        ear_anchor=ear_anchor,
    )


def key_attest_profile(
    *,
    request_type_oid: str,
    statement_oid: str,
    verifier: AttestationVerifier | None = None,
    verifier_url: str | None = None,
    reference_handler: VerifierReferenceHandler | None = None,
    ear_oid: str | None = None,
    resp_info_label: str = "KeyAttestResp",
    ear_anchor: TrustAnchor | None = None,
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for v5 TPM key attestation (credential activation).

    Unlike :func:`tpm_profile` / :func:`jwt_profile`, the respInfo is not a pure
    function of the client's reqInfo — it is produced by a *verifier round-trip*.
    The ``build_challenge`` hook decodes the client ``KeyAttestChall``, asks the
    verifier to run software ``TPM2_MakeCredential`` (via
    :meth:`VeraisonVerifierClient.make_credential`), and returns
    ``(KeyAttestResp DER, sessionId)``; the engine binds that session id to the
    nonce and embeds the ``KeyAttestResp`` in ``NonceResponse.respInfo``.

    ``build_resp_info`` / ``resp_info_to_json`` are inert stubs here (respInfo
    comes from ``build_challenge``, and it is carried as ASN.1 to the client, not
    forwarded as JSON to the verifier).  Registered under BOTH ``request_type_oid``
    and ``statement_oid`` by the caller, mirroring the certify block it replaces.

    The ASN.1 adapters are imported at call time so importing :mod:`libattest.ra`
    never pulls the key-attest format module.
    """
    from libattest.formats.key_attest_pop import (  # noqa: PLC0415
        key_attest_chall_to_json,
        key_attest_resp_from_json,
    )

    def build_challenge(
        req_info: bytes | None,
        challenge_verifier: AttestationVerifier,
    ) -> tuple[bytes | None, str | None]:
        if not req_info:
            raise ValueError("key-attest NonceRequest carries no KeyAttestChall reqInfo")
        make_credential = getattr(challenge_verifier, "make_credential", None)
        if make_credential is None:
            raise TypeError(f"key-attest verifier {type(challenge_verifier).__name__} has no make_credential()")
        chall = key_attest_chall_to_json(bytes(req_info))
        result = make_credential(
            ak_name=chall["akName"],
            ek_public=chall["ekPublic"],
            ek_cert_chain_pem=chall["ekCertChain"],
        )
        return key_attest_resp_from_json(result), result.get("sessionId")

    return AttestationProfile(
        request_type_oid=request_type_oid,
        statement_oid=statement_oid,
        build_resp_info=lambda _proposed: None,  # respInfo is produced by build_challenge
        resp_info_to_json=lambda _der: {},  # respInfo is not forwarded to the verifier as JSON
        resp_info_label=resp_info_label,
        build_challenge=build_challenge,
        binds_subject_key=True,
        encode_ear_extension=_default_encode_ear_extension(_effective_ear_extension_oid(ear_oid)),
        verifier=verifier,
        verifier_url=verifier_url,
        reference_handler=reference_handler,
        ear_anchor=ear_anchor,
    )


def hpke_profile(
    *,
    verifier: AttestationVerifier,
    statement_oid: str,
    request_type_oid: str | None = None,
    reference_handler: VerifierReferenceHandler | None = None,
    ear_oid: str | None = None,
    resp_info_label: str = "EvidenceEncryptionKey",
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for HPKE-encrypted Evidence.

    This is what makes the privacy-preserving demo verifiers drivable by the ordinary
    RA engine.  They used to sit outside it: ``EarEatHpkeVerifier.nonce_response()``
    assembled a whole ``NonceResponse`` itself, so the HPKE exchange got none of the
    engine's nonce lifecycle, none of its Relying Party appraisal, and no route through
    the profile registry — a second RA, in miniature, beside the real one.

    Everything the exchange needs is read off the verifier and declared on the profile:

    * ``respInfo`` publishes the verifier's HPKE recipient key (SubjectPublicKeyInfo
      DER), which is the verifier information the attester must have before it can
      encrypt anything;
    * ``media_type`` and ``verifier_id`` are taken from the verifier, so the RA sends
      the right media type and selects the EAR trust anchor by a *configured* name
      rather than by the developer claim inside the unverified token;
    * ``ear_anchor`` is pinned to the verifier's published EAR verification key when it
      publishes one, so an :class:`~libattest.ra.relying_party.EarAcceptancePolicy`
      needs no separate configuration for an in-process verifier.

    Parameters
    ----------
    verifier:
        An HPKE verifier — anything exposing ``evidence_encryption_spki_der()``; the
        optional ``verifier_id``, ``media_type`` and ``ear_verification_pem()`` are used
        when present.
    statement_oid:
        The ``AttestationStatement.type`` OID of the encrypted evidence, e.g.
        ``get_oid_by_name("jose-hpke-evidence")`` or ``"cose-hpke-evidence"``.
    request_type_oid:
        The ``NonceRequest.reqTypeInfo.type`` the attester sends to ask for the
        verifier's key.  Defaults to the registered HPKE evidence-parameters OID —
        which is one type ("publish your recipient key"), shared by both transports.
        A deployment offering **both** the JOSE and the COSE profile at once must
        therefore give one of them a distinct ``request_type_oid``, or the second
        registration shadows the first on the nonce-issue side; ``ProfileRegistry``
        warns when that happens.
    reference_handler:
        Optional reference-value check composed onto the verifier, as for the other
        factories.
    ear_oid:
        X.509 extension OID the issued EAR is embedded under; defaults to the
        environment's ``EAR_OID``.
    resp_info_label:
        Human-readable name of the respInfo payload, for operator logs.

    """
    publish_key: Callable[[], bytes] | None = getattr(verifier, "evidence_encryption_spki_der", None)
    if not callable(publish_key):
        raise TypeError(
            f"hpke_profile needs a verifier that publishes its recipient key; "
            f"{type(verifier).__name__} has no evidence_encryption_spki_der()"
        )
    published_key: Callable[[], bytes] = publish_key

    ear_pem: Callable[[], str] | None = getattr(verifier, "ear_verification_pem", None)
    params_oid = request_type_oid or get_nonce_request_oid_for_name("jose-hpke-evidence-params")
    return AttestationProfile(
        request_type_oid=params_oid,
        response_type_oid=get_nonce_response_oid_for_name("jose-hpke-evidence-params"),
        statement_oid=statement_oid,
        # The published key is a constant of the verifier, not a function of the
        # client's proposal, so there is nothing to negotiate here.
        build_resp_info=lambda _proposed: published_key(),
        resp_info_to_json=lambda _der: {},  # the verifier already holds the private half
        resp_info_label=resp_info_label,
        unwrap_statement=_cmw_is_the_statement,
        encode_ear_extension=_default_encode_ear_extension(_effective_ear_extension_oid(ear_oid)),
        verifier=verifier,
        reference_handler=reference_handler,
        verifier_id=getattr(verifier, "verifier_id", None),
        media_type=getattr(verifier, "media_type", None),
        ear_anchor=ear_pem() if callable(ear_pem) else None,
    )


def se05x_profile(
    *,
    verifier: Se05xAttestVerifier,
    binds_subject_key: bool = True,
    reference_handler: VerifierReferenceHandler | None = None,
    ear_oid: str | None = None,
) -> AttestationProfile:
    """Build an :class:`AttestationProfile` for NXP SE05x attested reads.

    Wires the ``se05x-attest-request`` / ``se05x-attest-response`` nonce types and the
    ``se05x-attest`` statement to an in-process
    :class:`~libattest.verifier.se05x.Se05xAttestVerifier`.  Nothing is negotiated (no
    reqInfo, no respInfo), and the statement is a DER ``Se05xAttestEvidence``
    SEQUENCE, so the default unwrap passes it through.  ``media_type``,
    ``verifier_id`` and ``ear_anchor`` are read off the verifier, so an
    :class:`~libattest.ra.relying_party.EarAcceptancePolicy` checks its EARs against
    the verifier's own EAR key with no further configuration.

    The deployment must issue 16-byte nonces, ``NonceStore(nonce_bytes=16)``: the SE
    signs the nonce unchanged as its freshness, and the verifier rejects any other
    length.  With *binds_subject_key* (the default) the caller must pass the CSR's
    SubjectPublicKeyInfo DER to ``engine.verify_bundle(..., pubkey=...)``; without it the
    engine refuses the statement.  The external MockCA does not pass one today.

    Parameters
    ----------
    verifier:
        The SE05x verifier that appraises the Evidence and issues the EAR.
    binds_subject_key:
        Whether the attested key (``TAG_1``) must equal the to-be-certified key.
    reference_handler:
        Optional reference-value check composed onto the verifier, as for the other
        factories.
    ear_oid:
        X.509 extension OID the issued EAR is embedded under; defaults to the
        environment's ``EAR_OID``.

    """
    return AttestationProfile(
        request_type_oid=get_nonce_request_oid_for_name("se05x-attest-request"),
        response_type_oid=get_nonce_response_oid_for_name("se05x-attest-response"),
        statement_oid=get_oid_for_stmt_name("se05x-attest"),
        build_resp_info=lambda _proposed: None,
        resp_info_to_json=lambda _der: {},
        encode_ear_extension=_default_encode_ear_extension(_effective_ear_extension_oid(ear_oid)),
        # The engine adapts any verifier with appraise(); the field's type predates that port.
        verifier=verifier,  # type: ignore[arg-type]
        reference_handler=reference_handler,
        binds_subject_key=binds_subject_key,
        verifier_id=verifier.verifier_id,
        media_type=verifier.media_type,
        ear_anchor=verifier.ear_verification_pem(),
    )


__all__ = [
    "AttestationProfile",
    "VerifierProvisioning",
    "hpke_profile",
    "jwt_profile",
    "key_attest_profile",
    "se05x_profile",
    "tpm_profile",
]
