# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 OID + UTF8String-JSON structures for TPM key attestation.

The v5 key-attestation nonce exchange keeps the outer CMP / ASN.1 layer simple
for OpenSSL-based clients.  The type-specific request and response payloads are
self-describing ASN.1 wrappers:

    KeyAttestChall ::= SEQUENCE { type OBJECT IDENTIFIER, value UTF8String }
    KeyAttestResp  ::= SEQUENCE { type OBJECT IDENTIFIER, value UTF8String }

``value`` contains deterministic JSON text.  The request JSON carries the AK /
requested-key TPM Name and EK certificate chain.  The response JSON carries only
``encSeed`` and ``encSecret``; the Verifier-generated ``seed`` is never sent to
the client and is retained by the CA/RA for proof-of-possession verification.

``KeyAttestPoP`` remains a normal ASN.1 X.509 extension value containing a
signature over the recovered ``seed``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import namedtype, univ
from pyasn1_alt_modules import rfc5280

from libattest.formats._oid_json import (
    OidUtf8Json,
    decode_oid_json_value,
    prepare_oid_json_value,
    resolve_env_oid,
)

KEY_ATTEST_POP_OID_ENV: str = "KEY_ATTEST_POP_OID"
DEFAULT_KEY_ATTEST_POP_OID: str = "1.3.6.1.4.1.99999.2"

KEY_ATTEST_CHALL_OID_ENV: str = "KEY_ATTEST_CHALL_OID"
DEFAULT_KEY_ATTEST_CHALL_OID: str = "1.3.6.1.4.1.99999.1.1"

KEY_ATTEST_RESP_OID_ENV: str = "KEY_ATTEST_RESP_OID"
DEFAULT_KEY_ATTEST_RESP_OID: str = "1.3.6.1.4.1.99999.1.2"

ID_SHA256_WITH_RSA_ENCRYPTION: str = "1.2.840.113549.1.1.11"
ID_ECDSA_WITH_SHA256: str = "1.2.840.10045.4.3.2"


def resolve_key_attest_pop_oid() -> str:
    """Return the private extension OID for ``KeyAttestPoP``."""
    return resolve_env_oid(KEY_ATTEST_POP_OID_ENV, DEFAULT_KEY_ATTEST_POP_OID)


def resolve_key_attest_chall_oid() -> str:
    """Return the JSON schema OID carried in ``KeyAttestChall.type``."""
    return resolve_env_oid(KEY_ATTEST_CHALL_OID_ENV, DEFAULT_KEY_ATTEST_CHALL_OID)


def resolve_key_attest_resp_oid() -> str:
    """Return the JSON schema OID carried in ``KeyAttestResp.type``."""
    return resolve_env_oid(KEY_ATTEST_RESP_OID_ENV, DEFAULT_KEY_ATTEST_RESP_OID)


class KeyAttestChall(OidUtf8Json):
    """``KeyAttestChall ::= SEQUENCE { type OID, value UTF8String }``."""


class KeyAttestResp(OidUtf8Json):
    """``KeyAttestResp ::= SEQUENCE { type OID, value UTF8String }``."""


class KeyAttestPoP(univ.Sequence):
    """``KeyAttestPoP ::= SEQUENCE { signatureAlgorithm, signature }``."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("signatureAlgorithm", rfc5280.AlgorithmIdentifier()),
        namedtype.NamedType("signature", univ.BitString()),
    )


@dataclass(frozen=True)
class VerifierMakeCredentialRequest:
    """CA/RA JSON request asking the Verifier to run MakeCredential."""

    transaction_id: str
    ak_name: bytes
    ek_cert_chain: Sequence[bytes]
    policy: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class VerifierMakeCredentialResult:
    """Verifier JSON result for delegated MakeCredential.

    ``seed`` is the CA/RA-side activation secret used for later PoP
    verification.  It MUST NOT be sent to the client.  ``encSeed`` and
    ``encSecret`` are copied into ``KeyAttestResp`` for TPM2_ActivateCredential.
    """

    seed: bytes
    enc_seed: bytes
    enc_secret: bytes


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


def prepare_key_attest_chall(
    ak_name: bytes,
    ek_cert_chain: Sequence[bytes],
) -> KeyAttestChall:
    """Build a client-to-CA/RA ``KeyAttestChall`` OID + JSON value."""
    payload = {
        "akName": ak_name.hex(),
        "ekCertChain": [cert.hex() for cert in ek_cert_chain],
    }
    return prepare_oid_json_value(KeyAttestChall, resolve_key_attest_chall_oid(), payload)


def prepare_key_attest_resp(enc_seed: bytes, enc_secret: bytes) -> KeyAttestResp:
    """Build the client-facing response from Verifier MakeCredential output."""
    payload = {
        "encSeed": enc_seed.hex(),
        "encSecret": enc_secret.hex(),
    }
    return prepare_oid_json_value(KeyAttestResp, resolve_key_attest_resp_oid(), payload)


def prepare_key_attest_pop(
    signature_algorithm: rfc5280.AlgorithmIdentifier,
    signature: bytes,
) -> KeyAttestPoP:
    """Build a ``KeyAttestPoP`` extension value."""
    value = KeyAttestPoP()
    value["signatureAlgorithm"] = signature_algorithm
    value["signature"] = univ.BitString.fromOctetString(signature)
    return value


def key_attest_chall_json_value(value: KeyAttestChall) -> dict[str, Any]:
    """Return the decoded application JSON payload from ``KeyAttestChall``."""
    return decode_oid_json_value(
        value,
        expected_oid=resolve_key_attest_chall_oid(),
        name="KeyAttestChall",
    )


def key_attest_resp_json_value(value: KeyAttestResp) -> dict[str, Any]:
    """Return the decoded application JSON payload from ``KeyAttestResp``."""
    return decode_oid_json_value(
        value,
        expected_oid=resolve_key_attest_resp_oid(),
        name="KeyAttestResp",
    )


def verifier_make_credential_request_to_json(
    request: VerifierMakeCredentialRequest,
) -> dict[str, Any]:
    """Encode a Verifier MakeCredential request as JSON-safe values."""
    data: dict[str, Any] = {
        "transactionID": request.transaction_id,
        "akName": request.ak_name.hex(),
        "ekCertChain": [cert.hex() for cert in request.ek_cert_chain],
    }
    if request.policy is not None:
        data["policy"] = dict(request.policy)
    return data


def verifier_make_credential_result_from_json(
    data: Mapping[str, Any],
) -> VerifierMakeCredentialResult:
    """Decode Verifier MakeCredential JSON with hex-encoded byte strings."""
    return VerifierMakeCredentialResult(
        seed=_decode_hex_field(data, "seed", "VerifierMakeCredentialResult"),
        enc_seed=_decode_hex_field(data, "encSeed", "VerifierMakeCredentialResult"),
        enc_secret=_decode_hex_field(data, "encSecret", "VerifierMakeCredentialResult"),
    )


def verifier_make_credential_result_to_json(
    result: VerifierMakeCredentialResult,
) -> dict[str, str]:
    """Encode Verifier MakeCredential result as JSON-safe hex strings."""
    return {
        "seed": result.seed.hex(),
        "encSeed": result.enc_seed.hex(),
        "encSecret": result.enc_secret.hex(),
    }


def encode_to_der(value: Any) -> bytes:
    """DER-encode any pyasn1 structure."""
    return bytes(_der_encoder.encode(value))


def decode_key_attest_chall(der: bytes) -> KeyAttestChall:
    """DER-decode bytes into a KeyAttestChall structure."""
    return _decode_der(der, KeyAttestChall(), "KeyAttestChall")


def decode_key_attest_resp(der: bytes) -> KeyAttestResp:
    """DER-decode bytes into a KeyAttestResp structure."""
    return _decode_der(der, KeyAttestResp(), "KeyAttestResp")


def decode_key_attest_pop(der: bytes) -> KeyAttestPoP:
    """DER-decode bytes into a KeyAttestPoP structure."""
    return _decode_der(der, KeyAttestPoP(), "KeyAttestPoP")


def _decode_der(der: bytes, asn1_spec, name: str):
    try:
        decoded, rest = _der_decoder.decode(der, asn1Spec=asn1_spec)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"failed to decode {name}: {exc}") from exc
    if rest:
        raise ValueError(f"trailing bytes after {name} SEQUENCE")
    return decoded


def key_attest_chall_ak_name(value: KeyAttestChall) -> bytes:
    """Extract the AK name bytes from a KeyAttestChall (hex-decoded from JSON payload)."""
    return _decode_hex_field(key_attest_chall_json_value(value), "akName", "KeyAttestChall")


def key_attest_chall_ek_cert_chain(value: KeyAttestChall) -> list[bytes]:
    """Extract the EK certificate chain from a KeyAttestChall as a list of DER bytes."""
    payload = key_attest_chall_json_value(value)
    chain = payload.get("ekCertChain")
    if not isinstance(chain, list):
        raise ValueError("KeyAttestChall: ekCertChain must be an array")
    result: list[bytes] = []
    for item in chain:
        if not isinstance(item, str):
            raise ValueError("KeyAttestChall: ekCertChain entries must be hex strings")
        try:
            result.append(bytes.fromhex(item))
        except ValueError as exc:
            raise ValueError("KeyAttestChall: ekCertChain entries must be valid hex") from exc
    return result


def key_attest_resp_enc_seed(value: KeyAttestResp) -> bytes:
    """Extract the encSeed bytes from a KeyAttestResp (hex-decoded from JSON payload)."""
    return _decode_hex_field(key_attest_resp_json_value(value), "encSeed", "KeyAttestResp")


def key_attest_resp_enc_secret(value: KeyAttestResp) -> bytes:
    """Extract the encSecret bytes from a KeyAttestResp (hex-decoded from JSON payload)."""
    return _decode_hex_field(key_attest_resp_json_value(value), "encSecret", "KeyAttestResp")


def key_attest_pop_algorithm_oid(value: KeyAttestPoP) -> str:
    """Return the signature algorithm OID string from a KeyAttestPoP."""
    return str(value["signatureAlgorithm"]["algorithm"])


def key_attest_pop_signature(value: KeyAttestPoP) -> bytes:
    """Return the raw signature bytes from a KeyAttestPoP."""
    return bytes(value["signature"].asOctets())


__all__ = [
    "DEFAULT_KEY_ATTEST_CHALL_OID",
    "DEFAULT_KEY_ATTEST_POP_OID",
    "DEFAULT_KEY_ATTEST_RESP_OID",
    "ID_ECDSA_WITH_SHA256",
    "ID_SHA256_WITH_RSA_ENCRYPTION",
    "KEY_ATTEST_CHALL_OID_ENV",
    "KEY_ATTEST_POP_OID_ENV",
    "KEY_ATTEST_RESP_OID_ENV",
    "KeyAttestChall",
    "KeyAttestPoP",
    "KeyAttestResp",
    "VerifierMakeCredentialRequest",
    "VerifierMakeCredentialResult",
    "decode_key_attest_chall",
    "decode_key_attest_pop",
    "decode_key_attest_resp",
    "encode_to_der",
    "key_attest_chall_ak_name",
    "key_attest_chall_ek_cert_chain",
    "key_attest_chall_json_value",
    "key_attest_pop_algorithm_oid",
    "key_attest_pop_signature",
    "key_attest_resp_enc_secret",
    "key_attest_resp_enc_seed",
    "key_attest_resp_json_value",
    "prepare_key_attest_chall",
    "prepare_key_attest_pop",
    "prepare_key_attest_resp",
    "resolve_key_attest_chall_oid",
    "resolve_key_attest_pop_oid",
    "resolve_key_attest_resp_oid",
    "verifier_make_credential_request_to_json",
    "verifier_make_credential_result_from_json",
    "verifier_make_credential_result_to_json",
]
