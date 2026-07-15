# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT HPKE evidence + nonce-exchange helpers (JOSE and COSE).

The reusable core of the JWT-HPKE demo, covering BOTH HPKE evidence profiles so the
attester, the verifier, and the MockCA share one wire contract. It composes the library's
existing structures instead of re-defining them:

* **CSR attestation-statement** structures — :func:`~libattest.formats.csrattest.prepare_attestation_statement`
  and :func:`~libattest.formats.csrattest.prepare_attestation_bundle` build the
  ``AttestationBundle`` carrying the encrypted evidence;
  :func:`~libattest.formats.csrattest.decode_attestation_bundle` reads it back.
* **CMP nonce-freshness** structures — :class:`~libattest.formats.csrattest.NonceRequest`
  and :class:`~libattest.formats.csrattest.NonceResponse` carry the freshness nonce and, in
  ``respInfo``, the verifier's HPKE recipient public key.
* the HPKE-0 sign/seal layer (:mod:`libattest.formats.eat_ear.cwt_jwt_utils`) and the CMW
  record codec (:func:`libattest.formats.cmw.encode_cmw_json_record` / ``decode_cmw_*_record``).

Two evidence profiles share this module:

* **JOSE-HPKE** (``build_evidence_*`` / ``extract_jwe_from_statement``): seals the signed
  EAT-JWS into a JOSE-HPKE JWE and carries it in a CMW ``json`` record
  (``["application/jose", <base64url JWE>, 4]``); freshness is bound in the JWE
  protected-header ``eat_nonce``.
* **COSE-HPKE** (``build_cose_evidence_*`` / ``generate_cwt_evidence`` /
  ``extract_cose_from_statement``): converts the EAT-JWS to CWT claims, nests a
  ``COSE_Sign1``, seals it with integrated COSE-HPKE-0 into a ``COSE_Encrypt0``, and carries
  the raw bytes in a CMW ``cbor`` record (``["application/cose", <COSE_Encrypt0>]``);
  freshness rides in the carried CWT ``eat_nonce`` claim (no separate outer-header binding).

Both HPKE-0 suites are DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM.

End-to-end flow (JOSE)::

    1. attester -> CA      NonceRequest(reqTypeInfo.type=EVIDENCE_ENC_PARAMS_OID) build_nonce_request
    2. CA/verifier -> att. NonceResponse(respTypeInfo.respInfo=HPKE SPKI)     build_evidence_enc_nonce_response
    3. attester            sign EAT, HPKE-seal, CMW-wrap, bundle           sign_and_build_evidence_bundle
    4. verifier            decode bundle -> HPKE-open -> verify -> appraise EarEatHpkeVerifier
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.type import univ

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1
from libattest.formats._oid_json import resolve_env_oid
from libattest.formats.cmw import (
    decode_cmw_cbor_record,
    decode_cmw_json_record,
    encode_cmw_json_record,
)
from libattest.formats.csrattest import (
    NonceRequest,
    NonceRequestTypeInfo,
    NonceResponse,
    NonceResponseTypeInfo,
    decode_attestation_bundle,
    prepare_attestation_bundle,
    prepare_attestation_statement,
)
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.media_types import CMW_MEDIA_COSE, CMW_MEDIA_JOSE
from libattest.stmt_log import log_statement

# ── JOSE-HPKE evidence ───────────────────────────────────────────────────────────
# AttestationStatement.type OID for HPKE-encrypted software evidence (distinct from the
# plaintext software-evidence OID 1.3.6.1.4.1.99999.1 so the MockCA routes it to the
# HPKE-capable verifier).
EVIDENCE_ENC_OID_ENV: str = "EVIDENCE_ENC_OID"
EVIDENCE_ENC_OID = "1.3.6.1.4.1.99999.10"
# NonceRequest/NonceResponse.type OID identifying the HPKE evidence-encryption key exchange.
EVIDENCE_ENC_PARAMS_OID = "1.3.6.1.4.1.99999.11"

CMW_TYPE_JOSE = 4  # CMW type indicator for a JOSE message (draft-ietf-rats-msg-wrap)
DEFAULT_KID = "eareat-hpke-verifier"

# ── COSE-HPKE evidence ───────────────────────────────────────────────────────────
# AttestationStatement.type OID for COSE-HPKE-encrypted software evidence. Distinct from the
# JOSE-HPKE OID above so the MockCA routes it to the COSE-capable verifier; matches
# gencmpclient's ATG_COSE_HPKE_STMT_TYPE_OID.
COSE_EVIDENCE_ENC_OID_ENV: str = "COSE_EVIDENCE_ENC_OID"
COSE_EVIDENCE_ENC_OID = cwt_jwt_utils.COSE_HPKE_STMT_TYPE_OID  # "1.3.6.1.4.1.99999.20"


def resolve_evidence_enc_oid() -> str:
    """Return the JOSE-HPKE-encrypted evidence statement OID (env-overridable)."""
    return resolve_env_oid(EVIDENCE_ENC_OID_ENV, EVIDENCE_ENC_OID)


def resolve_cose_evidence_enc_oid() -> str:
    """Return the COSE-HPKE-encrypted evidence statement OID (env-overridable)."""
    return resolve_env_oid(COSE_EVIDENCE_ENC_OID_ENV, COSE_EVIDENCE_ENC_OID)


# ── shared bundle / CMW helpers (used by both the JOSE and COSE bridges) ──────────
def _evidence_bundle_der(statement: Any) -> bytes:
    """DER-encode a one-statement ``AttestationBundle``."""
    return encode_to_der(prepare_attestation_bundle([statement]))


def _cmw_value_of_media(
    stmt_der: bytes,
    decode_record: Callable[[bytes], tuple[Any, Any, Any]],
    expected_media: str,
) -> Any:
    """Decode a CMW record from ``stmt`` DER and return its value, enforcing the media type.

    :raises ValueError: the record's media type is not *expected_media*.
    """
    media_type, value, _cmw_type = decode_record(stmt_der)
    if media_type != expected_media:
        raise ValueError(f"unexpected CMW media type {media_type!r}; expected {expected_media!r}")
    return value


def first_statement_der(bundle_der: bytes) -> bytes:
    """Decode an ``AttestationBundle`` DER and return its first statement's ``stmt`` DER."""
    bundle = decode_attestation_bundle(bundle_der)
    statements = bundle["attestations"]
    if not statements:
        raise ValueError("AttestationBundle carries no statements")
    return bytes(statements[0]["stmt"])


# ── HPKE recipient key <-> SPKI DER (the NonceResponse.respTypeInfo.respInfo payload) ──
def hpke_key_to_spki_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialise the verifier's HPKE recipient public key as SubjectPublicKeyInfo DER."""
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def hpke_key_from_spki_der(der: bytes) -> ec.EllipticCurvePublicKey:
    """Load an HPKE recipient public key from SubjectPublicKeyInfo DER."""
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("evidence-encryption key must be an EC (P-256) public key")
    return key


# ── JOSE-HPKE: build the encrypted-evidence bundle ───────────────────────────────
def build_evidence_statement(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey | dict[str, Any],
    *,
    nonce: bytes,
    kid: str = DEFAULT_KID,
    statement_oid: str = EVIDENCE_ENC_OID,
):
    """Seal *eat_jws* for the recipient and wrap it as one ``AttestationStatement``.

    Produces ``AttestationStatement{ type=statement_oid, stmt=DER(CMW json record) }``
    where the CMW record is ``["application/jose", <base64url compact JWE>, 4]`` and
    the JWE is the HPKE-0 seal of *eat_jws* bound to *nonce* (protected-header
    ``eat_nonce``).
    """
    header = {"alg": cwt_jwt_utils.HPKE0_ALG, "kid": kid, "eat_nonce": cwt_jwt_utils.b64u_encode(nonce)}
    jwe = cwt_jwt_utils.seal_integrated(eat_jws.encode("ascii"), header, recipient_hpke)
    encoded_jwe = cwt_jwt_utils.b64u_encode(jwe.encode("ascii"))
    cmw_der = encode_cmw_json_record(CMW_MEDIA_JOSE, encoded_jwe, CMW_TYPE_JOSE)
    statement = prepare_attestation_statement(univ.ObjectIdentifier(statement_oid), cmw_der)
    log_statement("HPKE evidence (JOSE)", statement, statement_oid)
    return statement


def build_evidence_bundle(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey | dict[str, Any],
    *,
    nonce: bytes,
    kid: str = DEFAULT_KID,
    statement_oid: str = EVIDENCE_ENC_OID,
) -> bytes:
    """Build the DER ``AttestationBundle`` carrying one JOSE-HPKE-encrypted evidence statement."""
    statement = build_evidence_statement(eat_jws, recipient_hpke, nonce=nonce, kid=kid, statement_oid=statement_oid)
    return _evidence_bundle_der(statement)


# The attester helper exposes the complete evidence-envelope call surface directly.
# pylint: disable=too-many-arguments
def sign_and_build_evidence_bundle(
    claims: dict[str, Any],
    signer_key: ec.EllipticCurvePrivateKey,
    recipient_hpke: ec.EllipticCurvePublicKey | dict[str, Any],
    *,
    nonce: bytes,
    kid: str = DEFAULT_KID,
    statement_oid: str = EVIDENCE_ENC_OID,
) -> bytes:
    """Sign an EAT-JWS over *claims* (binding *nonce*) then build the encrypted bundle.

    The attester one-shot: stamps ``eat_nonce`` into *claims*, ES256-signs the EAT with
    *signer_key*, HPKE-seals it to *recipient_hpke*, and returns the bundle DER.
    """
    eat_claims = {**claims, "eat_nonce": cwt_jwt_utils.b64u_encode(nonce)}
    eat_jws = cwt_jwt_utils.sign_es256(eat_claims, signer_key)
    return build_evidence_bundle(eat_jws, recipient_hpke, nonce=nonce, kid=kid, statement_oid=statement_oid)


# pylint: enable=too-many-arguments
def extract_jwe_from_statement(stmt_der: bytes) -> str:
    """Return the compact JWE from a CMW ``json`` evidence statement (``stmt`` DER).

    :raises ValueError: the statement is not a CMW
        ``["application/jose", <base64url jwe>, ...]`` record.
    """
    value = _cmw_value_of_media(stmt_der, decode_cmw_json_record, CMW_MEDIA_JOSE)
    try:
        return cwt_jwt_utils.b64u_decode(value).decode("ascii")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("CMW JOSE record does not contain a base64url compact JWE") from exc


# ── COSE-HPKE: build the encrypted-evidence bundle ───────────────────────────────
def generate_cwt_evidence(
    eat_jws: str | bytes,
    recipient_hpke: ec.EllipticCurvePublicKey,
    signer_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    """Return ``DER(CMW cbor)`` carrying COSE-HPKE-encrypted CWT evidence.

    A third-party CMP client supplies the statement type OID and inserts this
    opaque result directly into ``AttestationStatement.stmt``.
    """
    eat_jws_bytes = eat_jws.encode("ascii") if isinstance(eat_jws, str) else bytes(eat_jws)
    cose = cwt_jwt_utils.seal_cose_hpke_evidence(eat_jws_bytes, recipient_hpke, signing_key=signer_key)
    cmw_der = encode_cmw_json_record(CMW_MEDIA_COSE, cose, cbor=True)
    log_statement("COSE-HPKE CWT evidence", cmw_der)
    return cmw_der


def build_cose_evidence_statement(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey,
    *,
    signer_key: ec.EllipticCurvePrivateKey,
    statement_oid: str = COSE_EVIDENCE_ENC_OID,
):
    """Sign-then-encrypt *eat_jws* for *recipient_hpke* and wrap it as one ``AttestationStatement``.

    Produces ``AttestationStatement{ type=statement_oid, stmt=DER(CMW cbor record) }`` where the
    CMW record is ``["application/cose", <COSE_Encrypt0 bytes>]`` and the ``COSE_Encrypt0`` is
    the COSE-HPKE-0 seal of a nested ``COSE_Sign1`` (over the CWT-mapped claims of *eat_jws*,
    signed under *signer_key*).  *recipient_hpke* MUST be an EC P-256 public key (HPKE-0's KEM).
    """
    cmw_der = generate_cwt_evidence(eat_jws, recipient_hpke, signer_key)
    return prepare_attestation_statement(univ.ObjectIdentifier(statement_oid), cmw_der)


def build_cose_evidence_bundle(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey,
    *,
    signer_key: ec.EllipticCurvePrivateKey,
    statement_oid: str = COSE_EVIDENCE_ENC_OID,
) -> bytes:
    """Build the DER ``AttestationBundle`` carrying one COSE-HPKE-encrypted evidence statement."""
    statement = build_cose_evidence_statement(
        eat_jws, recipient_hpke, signer_key=signer_key, statement_oid=statement_oid
    )
    return _evidence_bundle_der(statement)


def extract_cose_from_statement(stmt_der: bytes) -> bytes:
    """Return raw ``COSE_Encrypt0`` bytes from a CMW ``cbor`` evidence statement.

    :raises ValueError: the statement is not a CMW
        ``["application/cose", <cose bytes>, ...]`` record.
    """
    return _cmw_value_of_media(stmt_der, decode_cmw_cbor_record, CMW_MEDIA_COSE)


# ── CMP nonce-freshness: carry the verifier HPKE key in respInfo ─────────────────
def build_nonce_request(*, length: int | None = 32, type_oid: str = EVIDENCE_ENC_PARAMS_OID) -> bytes:
    """Build the attester's ``NonceRequest`` DER for the HPKE evidence-encryption exchange."""
    request = NonceRequest()
    if length is not None:
        request["len"] = length
    type_info = NonceRequestTypeInfo()
    type_info["type"] = univ.ObjectIdentifier(type_oid)
    request["reqTypeInfo"] = type_info
    return encode_to_der(request)


def build_evidence_enc_nonce_response(
    nonce: bytes,
    hpke_public_key: ec.EllipticCurvePublicKey,
    *,
    type_oid: str = EVIDENCE_ENC_PARAMS_OID,
    expiry: int | None = None,
) -> bytes:
    """Build the ``NonceResponse`` DER that hands the attester the nonce + verifier HPKE key.

    ``respInfo`` carries the verifier's HPKE recipient public key as SubjectPublicKeyInfo
    DER (an ANY payload selected by ``respTypeInfo.type``).
    """
    response = NonceResponse()
    # Assign the raw Python value for the size-constrained ``nonce`` field; wrapping it in
    # an unconstrained univ.OctetString trips pyasn1's subtype/constraint check.
    response["nonce"] = nonce
    if expiry is not None:
        response["expiry"] = expiry
    type_info = NonceResponseTypeInfo()
    type_info["type"] = univ.ObjectIdentifier(type_oid)
    type_info["respInfo"] = univ.Any(hpke_key_to_spki_der(hpke_public_key))
    response["respTypeInfo"] = type_info
    return encode_to_der(response)


def parse_evidence_enc_nonce_response(
    der: bytes,
) -> tuple[bytes, ec.EllipticCurvePublicKey | None, str | None]:
    """Parse a ``NonceResponse`` DER into ``(nonce, hpke_public_key, type_oid)``.

    ``hpke_public_key`` is ``None`` when the response carries no ``respInfo`` (e.g. a
    zero-length nonce meaning "no freshness proof required").
    """
    response = try_decode_pyasn1(der, NonceResponse)
    nonce = bytes(response["nonce"])
    resp_type_info = response["respTypeInfo"]
    type_oid = str(resp_type_info["type"]) if resp_type_info.isValue else None
    hpke_key = None
    if resp_type_info.isValue and resp_type_info["respInfo"].isValue:
        hpke_key = hpke_key_from_spki_der(bytes(resp_type_info["respInfo"]))
    return nonce, hpke_key, type_oid


__all__ = [
    # JOSE-HPKE evidence
    "CMW_MEDIA_JOSE",
    "CMW_TYPE_JOSE",
    "DEFAULT_KID",
    "EVIDENCE_ENC_OID",
    "EVIDENCE_ENC_OID_ENV",
    "EVIDENCE_ENC_PARAMS_OID",
    "build_evidence_bundle",
    "build_evidence_statement",
    "extract_jwe_from_statement",
    "resolve_evidence_enc_oid",
    "sign_and_build_evidence_bundle",
    # COSE-HPKE evidence
    "CMW_MEDIA_COSE",
    "COSE_EVIDENCE_ENC_OID",
    "COSE_EVIDENCE_ENC_OID_ENV",
    "build_cose_evidence_bundle",
    "build_cose_evidence_statement",
    "extract_cose_from_statement",
    "generate_cwt_evidence",
    "resolve_cose_evidence_enc_oid",
    # shared
    "first_statement_der",
    # CMP nonce-freshness
    "build_evidence_enc_nonce_response",
    "build_nonce_request",
    "hpke_key_from_spki_der",
    "hpke_key_to_spki_der",
    "parse_evidence_enc_nonce_response",
]
