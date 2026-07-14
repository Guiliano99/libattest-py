# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Typed ASN.1 structures for the v5 TPM key-attestation (credential-activation) flow.

Three self-contained DER SEQUENCEs carry the whole exchange — no CMW wrapper, no
JSON-in-ASN.1::

    KeyAttestChall ::= SEQUENCE {          -- client → CA/RA (NonceRequest.reqInfo)
        akName       OCTET STRING,         -- TPM Name of the AK
        ekPublic     OCTET STRING,         -- marshalled TPM2B_PUBLIC of the EK
        ekCertChain  SEQUENCE OF Certificate }

    KeyAttestResp ::= SEQUENCE {           -- CA/RA → client (NonceResponse.respInfo)
        encSeed      OCTET STRING,         -- marshalled TPM2B_ENCRYPTED_SECRET
        encSecret    OCTET STRING }        -- marshalled TPM2B_ID_OBJECT

    KeyAttestEvidence ::= SEQUENCE {       -- client → CA/RA (AttestationStatement.stmt)
        tcgCertifyInfo      OCTET STRING,  -- marshalled TPMS_ATTEST (TPM_ST_ATTEST_CERTIFY)
        tpmSignature        OCTET STRING,  -- marshalled TPMT_SIGNATURE: AK over tcgCertifyInfo
        tpmTPublic          OCTET STRING,  -- bare marshalled TPMT_PUBLIC of the subject key
        keyAttestSignature  OCTET STRING } -- marshalled TPMT_SIGNATURE: subject key over H(seed)

The Verifier-generated ``seed`` is NEVER carried here; it is retained by the
Verifier for proof-of-possession verification.  ``encSeed``/``encSecret`` are the
opaque MakeCredential blobs the client feeds to ``TPM2_ActivateCredential``.

The ``*_to_json`` / ``*_from_json`` adapters are the single translation point the
RA engine uses across the JSON-only MockCA↔Verifier hop; ``mock_ca/`` never parses
these SEQUENCEs itself.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from typing import Any

from pyasn1.type import namedtype, univ
from pyasn1_alt_modules import rfc9480

from libattest.asn1_utils import encode_to_der, try_decode_pyasn1
from libattest.formats._oid_json import resolve_env_oid
from libattest.formats.csrattest.csr_attest_structures import pem_chain_to_cmp_certs

KEY_ATTEST_EVIDENCE_OID_ENV: str = "KEY_ATTEST_EVIDENCE_OID"
DEFAULT_KEY_ATTEST_EVIDENCE_OID: str = "1.3.6.1.4.1.99999.2"

#: Default statement OID as dotted string / pyasn1 OID.  The RA profile resolves
#: the effective OID via :func:`resolve_key_attest_evidence_oid` (env-overridable);
#: these constants are the convenience default for routing tables.
ID_KEY_ATTEST_EVIDENCE_DOTTED: str = DEFAULT_KEY_ATTEST_EVIDENCE_OID
ID_KEY_ATTEST_EVIDENCE: univ.ObjectIdentifier = univ.ObjectIdentifier(DEFAULT_KEY_ATTEST_EVIDENCE_OID)


def resolve_key_attest_evidence_oid() -> str:
    """Return the ``id-keyAttestEvidence`` statement OID (env-overridable)."""
    return resolve_env_oid(KEY_ATTEST_EVIDENCE_OID_ENV, DEFAULT_KEY_ATTEST_EVIDENCE_OID)


# ── typed ASN.1 structures ───────────────────────────────────────────────────


class EkCertChain(univ.SequenceOf):
    """``SEQUENCE OF Certificate`` — the EK certificate chain in a KeyAttestChall."""

    componentType = rfc9480.CMPCertificate()


class KeyAttestChall(univ.Sequence):
    """``KeyAttestChall ::= SEQUENCE { akName, ekPublic, ekCertChain }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("akName", univ.OctetString()),
        namedtype.NamedType("ekPublic", univ.OctetString()),
        namedtype.NamedType("ekCertChain", EkCertChain()),
    )


class KeyAttestResp(univ.Sequence):
    """``KeyAttestResp ::= SEQUENCE { encSeed, encSecret }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("encSeed", univ.OctetString()),
        namedtype.NamedType("encSecret", univ.OctetString()),
    )


class KeyAttestEvidence(univ.Sequence):
    """``KeyAttestEvidence ::= SEQUENCE { tcgCertifyInfo, tpmSignature, tpmTPublic, keyAttestSignature }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tcgCertifyInfo", univ.OctetString()),
        namedtype.NamedType("tpmSignature", univ.OctetString()),
        namedtype.NamedType("tpmTPublic", univ.OctetString()),
        namedtype.NamedType("keyAttestSignature", univ.OctetString()),
    )


# ── builders ─────────────────────────────────────────────────────────────────


def prepare_key_attest_chall(
    ak_name: bytes,
    ek_public: bytes,
    ek_cert_chain_pem: str,
) -> KeyAttestChall:
    """Build a client ``KeyAttestChall`` from the AK name, marshalled EK public, and PEM chain."""
    value = KeyAttestChall()
    value["akName"] = ak_name
    value["ekPublic"] = ek_public
    value["ekCertChain"].extend(pem_chain_to_cmp_certs(ek_cert_chain_pem))
    return value


def prepare_key_attest_resp(enc_seed: bytes, enc_secret: bytes) -> KeyAttestResp:
    """Build a ``KeyAttestResp`` from the MakeCredential blobs."""
    value = KeyAttestResp()
    value["encSeed"] = enc_seed
    value["encSecret"] = enc_secret
    return value


def prepare_key_attest_evidence(
    tcg_certify_info: bytes,
    tpm_signature: bytes,
    tpm_tpublic: bytes,
    key_attest_signature: bytes,
) -> KeyAttestEvidence:
    """Build a ``KeyAttestEvidence`` from the four marshalled-TPM byte fields."""
    value = KeyAttestEvidence()
    value["tcgCertifyInfo"] = tcg_certify_info
    value["tpmSignature"] = tpm_signature
    value["tpmTPublic"] = tpm_tpublic
    value["keyAttestSignature"] = key_attest_signature
    return value


# ── DER codecs ───────────────────────────────────────────────────────────────


def decode_key_attest_chall(der: bytes) -> KeyAttestChall:
    """DER-decode bytes into a :class:`KeyAttestChall`."""
    return try_decode_pyasn1(der, KeyAttestChall)


def decode_key_attest_resp(der: bytes) -> KeyAttestResp:
    """DER-decode bytes into a :class:`KeyAttestResp`."""
    return try_decode_pyasn1(der, KeyAttestResp)


def decode_key_attest_evidence(der: bytes) -> KeyAttestEvidence:
    """DER-decode bytes into a :class:`KeyAttestEvidence`."""
    return try_decode_pyasn1(der, KeyAttestEvidence)


# ── JSON adapters (RA engine ↔ Verifier, the single translation point) ────────


def _decode_hex_field(data: Mapping[str, Any], key: str, owner: str) -> bytes:
    try:
        value = data[key]
    except KeyError as exc:
        raise ValueError(f"{owner}: missing field {key}") from exc
    if not isinstance(value, str):
        raise ValueError(f"{owner}: field {key} must be a hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{owner}: field {key} must be a valid hex string") from exc


def _cert_to_pem(cert: rfc9480.CMPCertificate) -> str:
    der = encode_to_der(cert)
    b64 = base64.b64encode(der).decode("ascii")
    body = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _certs_to_pem(certs: Iterable[rfc9480.CMPCertificate]) -> str:
    return "".join(_cert_to_pem(cert) for cert in certs)


def key_attest_chall_to_json(chall_der: bytes) -> dict[str, str]:
    """Decode a ``KeyAttestChall`` DER into the JSON the engine POSTs to ``/makeCredential``.

    Returns ``{akName: hex, ekPublic: hex, ekCertChain: PEM}``.  ``ekCertChain`` is a
    single concatenated PEM string (one ``BEGIN CERTIFICATE`` block per cert).
    """
    chall = decode_key_attest_chall(chall_der)
    return {
        "akName": bytes(chall["akName"]).hex(),
        "ekPublic": bytes(chall["ekPublic"]).hex(),
        "ekCertChain": _certs_to_pem(chall["ekCertChain"]),
    }


def key_attest_resp_from_json(data: Mapping[str, Any]) -> bytes:
    """Build ``KeyAttestResp`` DER from the Verifier's ``{encSeed, encSecret}`` (hex) reply.

    This is what the MockCA embeds in ``NonceResponse.respInfo``.
    """
    resp = prepare_key_attest_resp(
        enc_seed=_decode_hex_field(data, "encSeed", "KeyAttestResp"),
        enc_secret=_decode_hex_field(data, "encSecret", "KeyAttestResp"),
    )
    return encode_to_der(resp)


def key_attest_resp_to_json(der: bytes | bytearray | univ.Any) -> dict[str, str]:
    """Decode ``KeyAttestResp`` DER into verifier JSON with hexadecimal blob fields."""
    resp = decode_key_attest_resp(bytes(der))
    return {
        "encSeed": bytes(resp["encSeed"]).hex(),
        "encSecret": bytes(resp["encSecret"]).hex(),
    }


__all__ = [
    "DEFAULT_KEY_ATTEST_EVIDENCE_OID",
    "ID_KEY_ATTEST_EVIDENCE",
    "ID_KEY_ATTEST_EVIDENCE_DOTTED",
    "KEY_ATTEST_EVIDENCE_OID_ENV",
    "EkCertChain",
    "KeyAttestChall",
    "KeyAttestEvidence",
    "KeyAttestResp",
    "decode_key_attest_chall",
    "decode_key_attest_evidence",
    "decode_key_attest_resp",
    "encode_to_der",
    "key_attest_chall_to_json",
    "key_attest_resp_from_json",
    "key_attest_resp_to_json",
    "prepare_key_attest_chall",
    "prepare_key_attest_evidence",
    "prepare_key_attest_resp",
    "resolve_key_attest_evidence_oid",
]
