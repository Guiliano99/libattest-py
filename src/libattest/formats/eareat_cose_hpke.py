# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Privacy-preserving EAR/EAT (COSE-HPKE-0) evidence-wrapping helpers.

COSE sibling of :mod:`libattest.formats.eareat_hpke`.  Where the JOSE demo seals
the signed EAT into a JOSE-HPKE JWE and carries it in a CMW ``json`` record
(``["application/jose", <jwe>, 4]``), this module:

1. converts the signed EAT-JWS to CWT claims, wraps them in a nested
   ``COSE_Sign1`` (signed under the attester's EAT key), and seals that with
   integrated COSE-HPKE-0 (draft-ietf-cose-hpke) into a ``COSE_Encrypt0`` — all
   done by :func:`libattest.attester.evidence_bridge.seal_cose_hpke_evidence`;
2. base64url-carries the ``COSE_Encrypt0`` bytes in the SAME CMW ``json`` record
   shape (media type ``application/cose``), so gencmpclient's ``d2i_ASN1_TYPE``
   carriage of ``AttestationStatement.stmt`` and the ``AttestationBundle``
   envelope stay byte-shape-identical to the proven JOSE path.

Freshness rides in the CWT ``eat_nonce`` claim carried verbatim from the input
EAT-JWS — there is no separate outer-header nonce binding (COSE-HPKE's protected
header carries only ``alg``); the verifier checks that single binding.  The
COSE-HPKE-0 profile is DHKEM(P-256,HKDF-SHA256)+HKDF-SHA256+AES-128-GCM, the
CBOR analog of the JOSE ``HPKE-0`` suite.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import univ

from libattest.formats.cose_hpke import (
    COSE_HPKE_STMT_TYPE_OID,
    seal_cose_hpke_evidence,
)
from libattest.formats import jose_jws
from libattest.formats._oid_json import resolve_env_oid
from libattest.formats.csrattest import (
    prepare_attestation_bundle,
    prepare_attestation_statement,
)

# Re-exported so verifier/tests can pull the bundle→first-statement helper from one place;
# the statement/bundle envelope is format-agnostic and shared with the JOSE demo.
from libattest.formats.eareat_hpke import first_statement_der
from libattest.x509 import decode_cmw_json_record, encode_cmw_json_record

# AttestationStatement.type OID for COSE-HPKE-encrypted software evidence.  Distinct from the
# JOSE-HPKE OID (eareat_hpke.EVIDENCE_ENC_OID = ...99999.10) so the MockCA routes it to the
# COSE-capable verifier; matches gencmpclient's ATG_COSE_HPKE_STMT_TYPE_OID and the crypto
# core's evidence_bridge.COSE_HPKE_STMT_TYPE_OID.
COSE_EVIDENCE_ENC_OID_ENV: str = "COSE_EVIDENCE_ENC_OID"
COSE_EVIDENCE_ENC_OID = COSE_HPKE_STMT_TYPE_OID  # "1.3.6.1.4.1.99999.20"

CMW_MEDIA_COSE = "application/cose"


def resolve_cose_evidence_enc_oid() -> str:
    """Return the COSE-HPKE-encrypted evidence statement OID (env-overridable)."""
    return resolve_env_oid(COSE_EVIDENCE_ENC_OID_ENV, COSE_EVIDENCE_ENC_OID)


def build_cose_evidence_statement(
    eat_jws: str,
    recipient_hpke: ec.EllipticCurvePublicKey,
    *,
    signer_key: ec.EllipticCurvePrivateKey,
    statement_oid: str = COSE_EVIDENCE_ENC_OID,
):
    """Sign-then-encrypt *eat_jws* for *recipient_hpke* and wrap it as one ``AttestationStatement``.

    Produces ``AttestationStatement{ type=statement_oid, stmt=DER(CMW json record) }`` where the
    CMW record is ``["application/cose", <base64url COSE_Encrypt0>]`` and the ``COSE_Encrypt0`` is
    the COSE-HPKE-0 seal of a nested ``COSE_Sign1`` (over the CWT-mapped claims of *eat_jws*,
    signed under *signer_key*).  *recipient_hpke* MUST be an EC P-256 public key (HPKE-0's KEM).
    """
    cose = seal_cose_hpke_evidence(eat_jws.encode("ascii"), recipient_hpke, signing_key=signer_key)
    cmw_der = encode_cmw_json_record(CMW_MEDIA_COSE, jose_jws.b64u_encode(cose))
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
    return _der_encoder.encode(prepare_attestation_bundle([statement]))


def extract_cose_from_statement(stmt_der: bytes) -> bytes:
    """Return the ``COSE_Encrypt0`` bytes from a CMW ``json`` COSE evidence statement (``stmt`` DER).

    :raises ValueError: the statement is not a CMW ``["application/cose", <b64url cose>, ...]`` record.
    """
    media_type, value, _cmw_type = decode_cmw_json_record(stmt_der)
    if media_type != CMW_MEDIA_COSE:
        raise ValueError(f"unexpected CMW media type {media_type!r}; expected {CMW_MEDIA_COSE!r}")
    return jose_jws.b64u_decode(value)


__all__ = [
    "CMW_MEDIA_COSE",
    "COSE_EVIDENCE_ENC_OID",
    "COSE_EVIDENCE_ENC_OID_ENV",
    "build_cose_evidence_bundle",
    "build_cose_evidence_statement",
    "extract_cose_from_statement",
    "first_statement_der",
    "resolve_cose_evidence_enc_oid",
]
