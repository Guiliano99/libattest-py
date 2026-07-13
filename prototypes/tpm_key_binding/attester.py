# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Attester side: produce key-binding Evidence from a TPM (or a software stand-in).

Two producers, one output shape (:class:`KeyBindingEvidence`):

* :class:`SyntheticKeyBindingAttester` — **no TPM required**. It mints genuine TPM
  wire structures (a real marshalled ``TPMT_PUBLIC`` via ``TPM2B_PUBLIC.from_pem``
  and a ``TPM_ST_ATTEST_CERTIFY`` ``TPMS_ATTEST``) but signs them with a software
  EC "AK". This is what the offline self-test and demo use, and it exercises the
  exact Verifier code a real TPM would.

* :class:`TpmKeyBindingAttester` — **real TPM**. It creates the Subject Key,
  ``TPM2_Certify``s it with the AK, and signs the nonce with the Subject Key.
  Runs only against a live TPM/simulator (e.g. ``docker/tpm-demo`` swtpm) and is
  therefore *not* covered by the offline self-test.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from evidence import KeyBindingEvidence
from key_attributes import (
    FIXEDPARENT,
    FIXEDTPM,
    SENSITIVEDATAORIGIN,
    SIGN_ENCRYPT,
    USERWITHAUTH,
)
from tpm2_pytss import TPM2_ALG, TPM2B_PUBLIC

from libattest.formats.tpm.tpm_name import compute_tpm_name
from libattest.formats.tpm.tpms_attest import TPM_GENERATED_VALUE

#: ``TPMS_ATTEST.type`` selector for a certify (TPM 2.0 Part 2, Table 152).
TPM_ST_ATTEST_CERTIFY = 0x8017

_TPM_ALG_ECDSA = 0x0018
_TPM_ALG_SHA256 = 0x000B

#: Attribute set for a *strong* Subject Key: TPM-resident, non-duplicable,
#: TPM-generated, and an unrestricted signing key (so it can also do the
#: operational proof-of-possession). Satisfies the strict default RP policy.
STRONG_SUBJECT_ATTRS = FIXEDTPM | FIXEDPARENT | SENSITIVEDATAORIGIN | USERWITHAUTH | SIGN_ENCRYPT

#: Attribute set for a *weak* Subject Key: duplicable and not TPM-bound — the
#: kind of key the draft's policy is designed to reject.
WEAK_SUBJECT_ATTRS = USERWITHAUTH | SIGN_ENCRYPT


def _tpm2b(buf: bytes) -> bytes:
    """Prefix *buf* with its UINT16 big-endian length (the TPM2B wire form)."""
    return struct.pack(">H", len(buf)) + buf


def _ecdsa_der_to_tpmt_signature(der_sig: bytes) -> bytes:
    """Re-encode a DER ECDSA signature as a raw ``TPMT_SIGNATURE`` (ECDSA/SHA-256).

    Lets the software-signed synthetic path feed the very same
    :func:`verify_tpm_signature` the real TPM path uses.
    """
    r, s = decode_dss_signature(der_sig)
    r_b = r.to_bytes(32, "big")
    s_b = s.to_bytes(32, "big")
    return b"".join(
        [
            struct.pack(">H", _TPM_ALG_ECDSA),  # sigAlg
            struct.pack(">H", _TPM_ALG_SHA256),  # signature.ecdsa.hash
            _tpm2b(r_b),  # signature.ecdsa.signatureR
            _tpm2b(s_b),  # signature.ecdsa.signatureS
        ]
    )


def _marshal_certify_attest(
    *,
    nonce: bytes,
    subject_name: bytes,
    qualified_signer: bytes = b"",
    qualified_name: bytes = b"",
) -> bytes:
    """Marshal a ``TPMS_ATTEST`` of type ``TPM_ST_ATTEST_CERTIFY``.

    Mirrors the exact bytes a real ``TPM2_Certify`` emits (Part 2 §10.12.8 +
    ``TPMS_CERTIFY_INFO``), so the Verifier's struct parsers read it identically.
    """
    return b"".join(
        [
            struct.pack(">I", TPM_GENERATED_VALUE),  # magic
            struct.pack(">H", TPM_ST_ATTEST_CERTIFY),  # type
            _tpm2b(qualified_signer),  # qualifiedSigner (AK Qualified Name)
            _tpm2b(nonce),  # extraData (qualifyingData / nonce)
            b"\x00" * 17,  # clockInfo (TPMS_CLOCK_INFO)
            b"\x00" * 8,  # firmwareVersion
            # attested union == TPMS_CERTIFY_INFO { name, qualifiedName }
            _tpm2b(subject_name),
            _tpm2b(qualified_name),
        ]
    )


def _subject_tpmt_public(subject_public: ec.EllipticCurvePublicKey, attrs: int) -> bytes:
    """Embed *subject_public* into a marshalled ``TPMT_PUBLIC`` with *attrs*.

    ``TPM2B_PUBLIC.from_pem`` builds a real public area whose ``unique`` point is
    exactly this key, so the certified public area, ``cnf``, and the PoP key are
    provably the same key.
    """
    pem = subject_public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    tpm2b = TPM2B_PUBLIC.from_pem(pem, nameAlg=TPM2_ALG.SHA256, objectAttributes=attrs)
    return tpm2b.publicArea.marshal()


@dataclass
class SyntheticKeyBindingAttester:
    """A software Attester that produces genuine-shaped TPM key-binding Evidence.

    The ``ak_private`` key stands in for the restricted TPM AK; ``subject_private``
    is the key being bound. See the module docstring for what is real vs. faked.
    """

    ak_private: ec.EllipticCurvePrivateKey
    subject_private: ec.EllipticCurvePrivateKey
    subject_attributes: int = STRONG_SUBJECT_ATTRS

    @classmethod
    def generate(cls, subject_attributes: int = STRONG_SUBJECT_ATTRS) -> "SyntheticKeyBindingAttester":
        """Create an attester with a fresh software AK and Subject Key."""
        return cls(
            ak_private=ec.generate_private_key(ec.SECP256R1()),
            subject_private=ec.generate_private_key(ec.SECP256R1()),
            subject_attributes=subject_attributes,
        )

    def ak_public_spki(self) -> bytes:
        """Return the stand-in AK public key as SubjectPublicKeyInfo DER."""
        return self.ak_private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def produce(self, nonce: bytes) -> KeyBindingEvidence:
        """Produce key-binding Evidence freshly bound to *nonce*."""
        tpmt_public = _subject_tpmt_public(self.subject_private.public_key(), self.subject_attributes)
        subject_name = compute_tpm_name(tpmt_public)

        attest = _marshal_certify_attest(nonce=nonce, subject_name=subject_name)
        # The restricted AK "signs" the TPM-generated certify statement.
        ak_der_sig = self.ak_private.sign(attest, ec.ECDSA(hashes.SHA256()))
        tpmt_signature = _ecdsa_der_to_tpmt_signature(ak_der_sig)

        # Operational proof-of-possession: the Subject *private* key signs the
        # nonce (a stand-in for the CSR/TLS signature the draft requires).
        pop_signature = self.subject_private.sign(nonce, ec.ECDSA(hashes.SHA256()))

        return KeyBindingEvidence(
            tpms_attest=attest,
            tpmt_signature=tpmt_signature,
            subject_tpmt_public=tpmt_public,
            ak_public_spki=self.ak_public_spki(),
            pop_signature=pop_signature,
        )


class TpmKeyBindingAttester:
    """Real-TPM Attester (design A1). Requires a connected, AK-provisioned TpmClient.

    Not covered by the offline self-test — run it against a live TPM/simulator
    (see the README for ``docker/tpm-demo`` steps).
    """

    def __init__(self, tpm) -> None:  # tpm: libattest.attester.tpm_client.TpmClient
        """Store a connected ``TpmClient`` whose AK has already been provisioned."""
        self._tpm = tpm

    def produce(self, nonce: bytes, *, subject_attributes: int = STRONG_SUBJECT_ATTRS) -> KeyBindingEvidence:
        """Create a Subject Key, ``TPM2_Certify`` it, and prove possession of it."""
        import hashlib

        from tpm2_pytss import (
            ESYS_TR,
            TPM2_RH,
            TPM2_ST,
            TPMT_PUBLIC,
            TPMT_SIG_SCHEME,
            TPMT_TK_HASHCHECK,
        )

        ectx = self._tpm.ectx
        if self._tpm.ak_handle is None:
            raise RuntimeError("provision the AK first (tpm.provision_ak())")

        # 1) Create the Subject Key: an unrestricted ECDSA signing key (so it can
        #    perform the PoP), TPM-resident and non-duplicable, as an OWNER primary.
        subject_template = TPMT_PUBLIC.parse(
            alg="ecc256:ecdsa-sha256:null",
            objectAttributes=subject_attributes,
            nameAlg=TPM2_ALG.SHA256,
        )
        subject_handle, subject_public, _, _, _ = ectx.create_primary(
            in_sensitive=None,
            in_public=TPM2B_PUBLIC(publicArea=subject_template),
            primary_handle=ESYS_TR.OWNER,
        )
        try:
            tpmt_public = subject_public.publicArea.marshal()

            # 2) TPM2_Certify the Subject Key with the AK; qualifyingData = nonce.
            #    A restricted AK forces its own scheme, so in_scheme is NULL.
            certify_info, ak_signature = ectx.certify(
                subject_handle,
                self._tpm.ak_handle,
                bytes(nonce),
                TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
            )

            # 3) Proof-of-possession: TPM2_Sign the nonce with the Subject Key.
            sign_scheme = TPMT_SIG_SCHEME(scheme=TPM2_ALG.ECDSA)
            sign_scheme.details.ecdsa.hashAlg = TPM2_ALG.SHA256
            null_ticket = TPMT_TK_HASHCHECK(tag=TPM2_ST.HASHCHECK, hierarchy=TPM2_RH.NULL, digest=b"")
            pop = ectx.sign(
                subject_handle,
                hashlib.sha256(bytes(nonce)).digest(),
                sign_scheme,
                null_ticket,
            )
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

            pop_signature = encode_dss_signature(
                int.from_bytes(bytes(pop.signature.ecdsa.signatureR), "big"),
                int.from_bytes(bytes(pop.signature.ecdsa.signatureS), "big"),
            )

            return KeyBindingEvidence(
                tpms_attest=bytes(certify_info),
                tpmt_signature=ak_signature.marshal(),
                subject_tpmt_public=tpmt_public,
                ak_public_spki=self._tpm.ak_public_der(),
                pop_signature=pop_signature,
            )
        finally:
            ectx.flush_context(subject_handle)


__all__ = [
    "STRONG_SUBJECT_ATTRS",
    "WEAK_SUBJECT_ATTRS",
    "TPM_ST_ATTEST_CERTIFY",
    "SyntheticKeyBindingAttester",
    "TpmKeyBindingAttester",
]
