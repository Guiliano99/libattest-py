# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT (JOSE-HPKE-0) evidence + nonce-exchange helpers.

This is the reusable core of the JWT-HPKE demo.  It deliberately composes the
library's existing structures instead of re-defining them, so the attester, the
verifier, and the MockCA all share one wire contract:

* **CSR attestation-statement** structures — :func:`~libattest.formats.csrattest.prepare_attestation_statement`
  and :func:`~libattest.formats.csrattest.prepare_attestation_bundle` build the
  ``AttestationBundle`` carrying the encrypted evidence;
  :func:`~libattest.formats.csrattest.decode_attestation_bundle` reads it back.
* **CMP nonce-freshness** structures — :class:`~libattest.formats.csrattest.NonceRequest`
  and :class:`~libattest.formats.csrattest.NonceResponse` carry the freshness
  nonce and, in ``respInfo``, the verifier's HPKE recipient public key (so the
  attester learns which key to encrypt Evidence to).
* the HPKE-0 JOSE/JWE layer (:mod:`libattest.formats.jose_hpke`), the ES256 JWS
  layer (:mod:`libattest.formats.jose_jws`), and the CMW record codec
  (:func:`libattest.x509.encode_cmw_json_record` / ``decode_cmw_json_record``).

End-to-end flow::

    1. attester -> CA      NonceRequest(type=EVIDENCE_ENC_PARAMS_OID)      build_nonce_request
    2. CA/verifier -> att. NonceResponse(nonce, respInfo=verifier HPKE SPKI) build_evidence_enc_nonce_response
    3. attester            sign EAT, HPKE-seal, CMW-wrap, bundle           sign_and_build_evidence_bundle
    4. verifier            decode bundle -> HPKE-open -> verify -> appraise EarEatHpkeVerifier
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import univ

from libattest.formats import jose_hpke, jose_jws
from libattest.formats.csrattest import (
    NonceRequest,
    NonceResponse,
    decode_attestation_bundle,
    prepare_attestation_bundle,
    prepare_attestation_statement,
)
from libattest.x509 import decode_cmw_json_record, encode_cmw_json_record

# AttestationStatement.type OID for HPKE-encrypted software evidence (distinct from the
# plaintext software-evidence OID 1.3.6.1.4.1.99999.1 so the MockCA routes it to the
# HPKE-capable verifier).
EVIDENCE_ENC_OID = "1.3.6.1.4.1.99999.10"
# NonceRequest/NonceResponse.type OID identifying the HPKE evidence-encryption key exchange.
EVIDENCE_ENC_PARAMS_OID = "1.3.6.1.4.1.99999.11"

CMW_MEDIA_JOSE = "application/jose"
CMW_TYPE_JOSE = 4  # CMW type indicator for a JOSE message (draft-ietf-rats-msg-wrap)
DEFAULT_KID = "eareat-hpke-verifier"


# ── HPKE recipient key <-> SPKI DER (the NonceResponse.respInfo payload) ─────────
def hpke_key_to_spki_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialise the verifier's HPKE recipient public key as SubjectPublicKeyInfo DER."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def hpke_key_from_spki_der(der: bytes) -> ec.EllipticCurvePublicKey:
    """Load an HPKE recipient public key from SubjectPublicKeyInfo DER."""
    key = serialization.load_der_public_key(der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("evidence-encryption key must be an EC (P-256) public key")
    return key


# ── CSR attestation-statement: build the encrypted-evidence bundle ───────────────
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
    where the CMW record is ``["application/jose", <compact JWE>, 4]`` and the JWE is the
    HPKE-0 seal of *eat_jws* bound to *nonce* (protected-header ``eat_nonce``).
    """
    header = {"alg": jose_hpke.ALG, "kid": kid, "eat_nonce": jose_jws.b64u_encode(nonce)}
    jwe = jose_hpke.seal_integrated(eat_jws.encode("ascii"), header, recipient_hpke)
    cmw_der = encode_cmw_json_record(CMW_MEDIA_JOSE, jwe, CMW_TYPE_JOSE)
    return prepare_attestation_statement(univ.ObjectIdentifier(statement_oid), cmw_der)


def build_evidence_bundle(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey | dict[str, Any],
    *,
    nonce: bytes,
    kid: str = DEFAULT_KID,
    statement_oid: str = EVIDENCE_ENC_OID,
) -> bytes:
    """Build the DER ``AttestationBundle`` carrying one HPKE-encrypted evidence statement."""
    statement = build_evidence_statement(
        eat_jws, recipient_hpke, nonce=nonce, kid=kid, statement_oid=statement_oid
    )
    return _der_encoder.encode(prepare_attestation_bundle([statement]))


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
    eat_claims = {**claims, "eat_nonce": jose_jws.b64u_encode(nonce)}
    eat_jws = jose_jws.sign_es256(eat_claims, signer_key)
    return build_evidence_bundle(
        eat_jws, recipient_hpke, nonce=nonce, kid=kid, statement_oid=statement_oid
    )


def extract_jwe_from_statement(stmt_der: bytes) -> str:
    """Return the compact JWE from a CMW ``json`` evidence statement (``stmt`` DER).

    :raises ValueError: the statement is not a CMW ``["application/jose", <jwe>, ...]`` record.
    """
    media_type, value, _cmw_type = decode_cmw_json_record(stmt_der)
    if media_type != CMW_MEDIA_JOSE:
        raise ValueError(f"unexpected CMW media type {media_type!r}; expected {CMW_MEDIA_JOSE!r}")
    return value


def first_statement_der(bundle_der: bytes) -> bytes:
    """Decode an ``AttestationBundle`` DER and return its first statement's ``stmt`` DER."""
    bundle = decode_attestation_bundle(bundle_der)
    statements = bundle["attestations"]
    if not len(statements):
        raise ValueError("AttestationBundle carries no statements")
    return bytes(statements[0]["stmt"])


# ── CMP nonce-freshness: carry the verifier HPKE key in respInfo ─────────────────
def build_nonce_request(*, length: int | None = 32, type_oid: str = EVIDENCE_ENC_PARAMS_OID) -> bytes:
    """Build the attester's ``NonceRequest`` DER for the HPKE evidence-encryption exchange."""
    request = NonceRequest()
    if length is not None:
        request["len"] = length
    request["type"] = univ.ObjectIdentifier(type_oid)
    return _der_encoder.encode(request)


def build_evidence_enc_nonce_response(
    nonce: bytes,
    hpke_public_key: ec.EllipticCurvePublicKey,
    *,
    type_oid: str = EVIDENCE_ENC_PARAMS_OID,
    expiry: int | None = None,
) -> bytes:
    """Build the ``NonceResponse`` DER that hands the attester the nonce + verifier HPKE key.

    ``respInfo`` carries the verifier's HPKE recipient public key as SubjectPublicKeyInfo
    DER (an ANY payload selected by ``type``).
    """
    response = NonceResponse()
    # Assign the raw Python value for the size-constrained ``nonce`` field; wrapping it in
    # an unconstrained univ.OctetString trips pyasn1's subtype/constraint check.
    response["nonce"] = nonce
    if expiry is not None:
        response["expiry"] = expiry
    response["type"] = univ.ObjectIdentifier(type_oid)
    response["respInfo"] = univ.Any(hpke_key_to_spki_der(hpke_public_key))
    return _der_encoder.encode(response)


def parse_evidence_enc_nonce_response(
    der: bytes,
) -> tuple[bytes, ec.EllipticCurvePublicKey | None, str | None]:
    """Parse a ``NonceResponse`` DER into ``(nonce, hpke_public_key, type_oid)``.

    ``hpke_public_key`` is ``None`` when the response carries no ``respInfo`` (e.g. a
    zero-length nonce meaning "no freshness proof required").
    """
    response, _ = _der_decoder.decode(der, asn1Spec=NonceResponse())
    nonce = bytes(response["nonce"])
    type_oid = str(response["type"]) if response["type"].isValue else None
    hpke_key = None
    if response["respInfo"].isValue:
        hpke_key = hpke_key_from_spki_der(bytes(response["respInfo"]))
    return nonce, hpke_key, type_oid


__all__ = [
    "CMW_MEDIA_JOSE",
    "CMW_TYPE_JOSE",
    "EVIDENCE_ENC_OID",
    "EVIDENCE_ENC_PARAMS_OID",
    "build_evidence_bundle",
    "build_evidence_enc_nonce_response",
    "build_evidence_statement",
    "build_nonce_request",
    "extract_jwe_from_statement",
    "first_statement_der",
    "hpke_key_from_spki_der",
    "hpke_key_to_spki_der",
    "parse_evidence_enc_nonce_response",
    "sign_and_build_evidence_bundle",
]
