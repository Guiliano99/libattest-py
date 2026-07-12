# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The Attester → Verifier key-binding message (design A1: native ``TPM2_Certify``).

draft-reddy-rats-key-binding-01 pictures the Attester signing an EAT with its AK.
A TPM AK is a *restricted* key, so it cannot sign an arbitrary EAT/JWT — it can
only sign TPM-internal data. Design **A1** therefore uses the TPM's own
``TPM2_Certify`` output as the AK-signed Evidence: the ``TPMS_ATTEST`` (type
``TPM_ST_ATTEST_CERTIFY``) binds the AK to the *Name* of the Subject Key, and the
Verifier derives the draft's ``cnf`` and ``key-attributes`` from the certified
public area. This is exactly the shape the repo's :class:`TcgAttestCertify`
already models (OID ``2.23.133.20.1``), so the evidence can ride inside an
existing ``AttestationBundle`` unchanged — see :meth:`KeyBindingEvidence.certify_der`.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyasn1.codec.der.encoder import encode as _der_encode

from libattest.formats.tpm.tcg import prepare_tcg_attest_certify


@dataclass(frozen=True)
class KeyBindingEvidence:
    """One key-binding Evidence message an Attester sends to a Verifier.

    Attributes
    ----------
    tpms_attest:
        The marshalled ``TPMS_ATTEST`` from ``TPM2_Certify`` (type
        ``TPM_ST_ATTEST_CERTIFY``). ``extraData`` carries the Verifier nonce;
        the ``attested`` union carries the certified Subject Key's Name.
    tpmt_signature:
        The raw wire ``TPMT_SIGNATURE`` the AK produced over *tpms_attest*.
    subject_tpmt_public:
        The marshalled ``TPMT_PUBLIC`` of the certified Subject Key. The Verifier
        checks ``compute_tpm_name(subject_tpmt_public)`` equals the Name inside
        *tpms_attest*, then reads ``key-attributes`` and ``cnf`` from it.
    ak_public_spki:
        The AK public key as SubjectPublicKeyInfo DER. Its trust (an AK
        certificate chain, or credential activation against an EK) is out of
        band — here it is assumed already trusted by Verifier policy.
    pop_signature:
        A DER ECDSA signature over the Verifier nonce, made with the Subject
        *private* key. Stands in for the draft's protocol-level proof-of-
        possession (the CSR or TLS signature): it proves the operational key is
        the same key the TPM certified, i.e. the one named in ``cnf``.

    """

    tpms_attest: bytes
    tpmt_signature: bytes
    subject_tpmt_public: bytes
    ak_public_spki: bytes
    pop_signature: bytes

    def certify_der(self) -> bytes:
        """Serialise the AK-signed triple as a repo ``TcgAttestCertify`` (DER).

        Demonstrates that this Evidence slots straight into the existing
        attestation-bundle machinery: the same SEQUENCE the platform-quote path
        already uses, under the key-attestation OID ``2.23.133.20.1``.
        """
        return _der_encode(
            prepare_tcg_attest_certify(
                self.tpms_attest, self.tpmt_signature, self.subject_tpmt_public
            )
        )


__all__ = ["KeyBindingEvidence"]
