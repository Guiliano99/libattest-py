# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""One-shot TPM evidence generator for the CSR-attestation seam.

The whole point of this module is a single call surface a non-Python client
(gencmpclient, embedding this via ``Py_Initialize``) can use without knowing
any TPM or ASN.1 structure: :func:`generate_tpm_evidence` drives the TPM
(``tpm2_pytss`` via :class:`~libattest.attester.tpm_client.TpmClient`), builds
the ``TcgAttestCertify``/``KeyAttestEvidence`` DER, and hands
back ``(evidence_der, type_oid)``. (TPM2_Quote and TPM2_Certify evidence share
the ``TcgAttestCertify`` wire shape; the outer OID distinguishes them.) The caller wraps that pair in an
``AttestationStatement``/``AttestationBundle`` — this module never sees that
envelope, mirroring how ``atg_generate_evidence`` hands the software EAR/EAT
path an opaque token plus its type OID.

:func:`build_key_attest_chall` is the matching nonce-time one-shot: it reads the
AK Name + EK public from the TPM and returns the ``KeyAttestChall`` DER the
client sends in the CMP ``NonceRequest.reqInfo``.

All parameters are positional-friendly (no keyword-only arguments) so the
CPython C-API glue can call this with a plain argument tuple.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from pyasn1.codec.der import encoder as der_encoder

from libattest.attester.tpm_client import TpmClient
from libattest.formats.cose_hpke import (
    COSE_HPKE_STMT_TYPE_OID,
    open_cose_hpke_evidence,
    seal_cose_hpke_evidence,
)
from libattest.formats.key_attest_pop import (
    decode_key_attest_resp,
    encode_to_der,
    prepare_key_attest_chall,
    prepare_key_attest_evidence,
    resolve_key_attest_evidence_oid,
)
from libattest.formats.tpm.tcg import (
    id_tcg_attest_certify,
    id_tcg_attest_quote,
    prepare_tcg_attest_certify,
)

_KINDS = ("quote", "certify", "key-attest")


def _corrupt_sig(signature_wire_bytes: bytes) -> bytes:
    """Flip one signature-payload bit for the negative-test hook (offset 6)."""
    if len(signature_wire_bytes) > 6:
        corrupted = bytearray(signature_wire_bytes)
        corrupted[6] ^= 0x01
        return bytes(corrupted)
    return signature_wire_bytes


def generate_tpm_evidence(
    kind: str,
    nonce: bytes | str,
    tcti: str,
    ak_handle: int,
    pcr_selection: str | None = None,
    subject_key_pem: str | None = None,
    corrupt_signature: bool = False,
    enc_seed: bytes | None = None,
    enc_secret: bytes | None = None,
) -> tuple[bytes, str]:
    """Drive the TPM and return ``(evidence_der, type_oid)`` for one evidence kind.

    Parameters
    ----------
    kind:
        ``"quote"`` (``TPM2_Quote`` over PCRs), ``"certify"`` (``TPM2_Certify`` of
        a subject key → ``TcgAttestCertify``), or ``"key-attest"`` (v5
        credential-activation → ``KeyAttestEvidence``). Selects both the TPM
        operation and the returned OID.
    nonce:
        The verifier's freshness nonce (qualifyingData).
    tcti:
        TCTI connection string (e.g. ``"mssim:host=tpmsim,port=2321"``).
    ak_handle:
        Persistent handle of the already-provisioned AK (e.g. ``0x81010002``).
        Never re-provisioned here — see :meth:`TpmClient.load_ak`.
    pcr_selection:
        ``kind="quote"`` only. tpm2-tools-style ``"bank:idx,idx,..."``. When
        omitted, falls back to :meth:`TpmClient.quote`'s own default.
    subject_key_pem:
        Required for ``kind="certify"`` and ``kind="key-attest"``. Path to the
        subject key's "TSS2 PRIVATE KEY" PEM (the key being certified — must be
        the same TPM key backing the CSR).
    corrupt_signature:
        Negative-test hook only — never set outside a negative-test run. Flips
        one bit of the AK signature so the verifier's AK-signature check rejects.
    enc_seed, enc_secret:
        Required for ``kind="key-attest"``. The marshalled MakeCredential blobs
        recovered from the Verifier's ``KeyAttestResp`` (``encSeed`` =
        ``TPM2B_ENCRYPTED_SECRET``, ``encSecret`` = ``TPM2B_ID_OBJECT``).

    Returns
    -------
    tuple[bytes, str]
        ``(evidence_der, type_oid)`` — the DER-encoded statement and its
        ``AttestationStatement.type`` OID (dotted-decimal). The caller treats
        ``evidence_der`` as opaque.

    Raises
    ------
    ValueError
        On an unknown ``kind`` or a missing kind-specific argument.

    """
    if kind not in _KINDS:
        raise ValueError(f"unknown kind {kind!r}; expected one of {_KINDS}")
    if kind == "certify" and not subject_key_pem:
        raise ValueError("kind='certify' requires subject_key_pem")
    if kind == "key-attest":
        # Explicit per-arg guards (not a loop) so the type checker narrows each
        # to non-None for the call below — no assert crutch needed.
        if not subject_key_pem:
            raise ValueError("kind='key-attest' requires subject_key_pem")
        if not enc_seed:
            raise ValueError("kind='key-attest' requires enc_seed")
        if not enc_secret:
            raise ValueError("kind='key-attest' requires enc_secret")
        return _generate_key_attest_evidence(
            nonce, tcti, ak_handle, subject_key_pem, enc_seed, enc_secret, corrupt_signature
        )

    with TpmClient(tcti=tcti) as tpm:
        tpm.load_ak(ak_handle)

        if kind == "quote":
            quote_kwargs = {"pcr_selection": pcr_selection} if pcr_selection else {}
            result = tpm.quote(nonce, include_pcr_values=True, **quote_kwargs)
            third_field = result.pcr_values or None
            type_oid = id_tcg_attest_quote
        else:
            result = tpm.certify(subject_key_pem, nonce)
            third_field = result.tpmt_public
            type_oid = id_tcg_attest_certify

    signature_wire_bytes = result.signature_wire_bytes
    if corrupt_signature:
        signature_wire_bytes = _corrupt_sig(signature_wire_bytes)

    statement = prepare_tcg_attest_certify(
        tpm_s_attest=result.attestation_bytes,
        signature=signature_wire_bytes,
        tpm_tpublic=third_field,
    )
    return der_encoder.encode(statement), str(type_oid)


def _generate_key_attest_evidence(
    nonce: bytes | str,
    tcti: str,
    ak_handle: int,
    subject_key_pem: str,
    enc_seed: bytes,
    enc_secret: bytes,
    corrupt_signature: bool,
) -> tuple[bytes, str]:
    """Build a ``KeyAttestEvidence`` statement (credential-activation PoP flow).

    The PoP ``sign(H(seed))`` needs the subject key still resident, so the whole
    statement is assembled inside the TPM session (certify keeps the subject
    loaded; ``close()`` flushes it on exit).
    """
    with TpmClient(tcti=tcti) as tpm:
        tpm.load_ak(ak_handle)
        tpm.provision_ek()  # deterministic EK primary; recreates the EK the chall advertised
        seed = tpm.recover_seed(enc_secret=enc_secret, enc_seed=enc_seed)
        result = tpm.certify(subject_key_pem, nonce, keep_subject_loaded=True)
        pop_signature = bytes(tpm.sign(hashlib.sha256(seed).digest()).marshal())
        ak_signature = result.signature_wire_bytes

    if corrupt_signature:
        ak_signature = _corrupt_sig(ak_signature)

    evidence = prepare_key_attest_evidence(
        tcg_certify_info=result.attestation_bytes,
        tpm_signature=ak_signature,
        tpm_tpublic=result.tpmt_public,
        key_attest_signature=pop_signature,
    )
    return encode_to_der(evidence), resolve_key_attest_evidence_oid()


def build_key_attest_chall(tcti: str, ak_handle: int, ek_cert_chain: str) -> bytes:
    """Return the ``KeyAttestChall`` DER for the CMP ``NonceRequest.reqInfo``.

    Reads the AK Name and the (deterministic) EK public from the TPM and pairs
    them with the client's EK certificate chain.  The Verifier uses ``ekPublic``
    to run ``TPM2_MakeCredential`` and ``akName`` as the bound Name.

    ``ek_cert_chain`` is either inline PEM or a path to a PEM file — the gencmpclient
    ``-ekCertChain`` flag passes a path.
    """
    # ponytail: accept a PEM path or inline PEM so the C bridge can pass a path.
    pem = ek_cert_chain if "-----BEGIN" in ek_cert_chain else Path(ek_cert_chain).read_text()
    with TpmClient(tcti=tcti) as tpm:
        tpm.load_ak(ak_handle)
        tpm.provision_ek()
        ak_name = bytes(tpm.ak_name)
        ek_public = bytes(tpm.ek_public.marshal())

    chall = prepare_key_attest_chall(ak_name=ak_name, ek_public=ek_public, ek_cert_chain_pem=pem)
    return encode_to_der(chall)


def generate_key_attest_evidence(
    nonce: bytes | str,
    tcti: str,
    ak_handle: int,
    subject_key_pem: str,
    key_attest_resp_der: bytes,
    corrupt_signature: bool = False,
) -> tuple[bytes, str]:
    """Evidence-time one-shot for the gencmpclient key-attest bridge.

    Decodes the ``KeyAttestResp`` (the CA's ``NonceResponse.respInfo``, carrying the
    MakeCredential blobs) and drives the ``"key-attest"`` evidence generation —
    keeping the C client free of the ``KeyAttestResp`` ASN.1.  Returns
    ``(evidence_der, type_oid)``.
    """
    resp = decode_key_attest_resp(bytes(key_attest_resp_der))
    return generate_tpm_evidence(
        "key-attest",
        nonce,
        tcti,
        ak_handle,
        subject_key_pem=subject_key_pem,
        corrupt_signature=corrupt_signature,
        enc_seed=bytes(resp["encSeed"]),
        enc_secret=bytes(resp["encSecret"]),
    )


__all__ = [
    "COSE_HPKE_STMT_TYPE_OID",
    "build_key_attest_chall",
    "generate_key_attest_evidence",
    "generate_tpm_evidence",
    "open_cose_hpke_evidence",
    "seal_cose_hpke_evidence",
]
