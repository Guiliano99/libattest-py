# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM key-attestation verifier."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from libattest.formats.key_attest_pop import (
    decode_key_attest_chall,
    decode_key_attest_pop,
    encode_to_der,
    key_attest_chall_ak_name,
    key_attest_chall_ek_cert_chain,
    prepare_key_attest_resp,
    verify_key_attest_pop,
)
from libattest.types import VerifyResult
from libattest.verifier.tpm.base import TpmReferenceVerifier

MakeCredentialCallback = Callable[..., tuple[bytes, bytes]]


@dataclass(frozen=True)
class TpmActivationChallenge:
    """Verifier-side state for a TPM2_ActivateCredential challenge.

    The verifier/CA stores ``seed`` and sends only ``response_der`` to the
    client.  The client TPM runs ``TPM2_ActivateCredential`` using the response
    blobs and proves possession by signing the recovered seed in ``KeyAttestPoP``.
    """

    transaction_id: str
    seed: bytes
    response_der: bytes


class TpmKeyAttestVerifier(TpmReferenceVerifier):
    """Verifier for TPM key-attestation evidence."""

    def build_activation_challenge(
        self,
        challenge_der: bytes,
        *,
        transaction_id: str,
        make_credential: MakeCredentialCallback,
        seed: bytes | None = None,
    ) -> TpmActivationChallenge:
        """Build the verifier side of the TPM2_ActivateCredential exchange.

        The verifier does not execute ``TPM2_ActivateCredential`` itself; that is
        the attester TPM operation.  The verifier generates/stores ``seed``, uses
        the supplied MakeCredential implementation to wrap it for ``(EK, AKName)``,
        and returns a ``KeyAttestResp`` carrying only ``encSeed``/``encSecret``.
        """
        challenge = decode_key_attest_chall(challenge_der)
        ak_name = key_attest_chall_ak_name(challenge)
        ek_cert_chain = key_attest_chall_ek_cert_chain(challenge)
        activation_seed = seed if seed is not None else secrets.token_bytes(32)
        enc_seed, enc_secret = make_credential(
            ak_name=ak_name,
            ek_cert_chain=ek_cert_chain,
            seed=activation_seed,
        )
        response = prepare_key_attest_resp(enc_seed=enc_seed, enc_secret=enc_secret)
        return TpmActivationChallenge(
            transaction_id=transaction_id,
            seed=activation_seed,
            response_der=encode_to_der(response),
        )

    def verify_activation_pop(
        self,
        *,
        seed: bytes,
        spki_der: bytes,
        pop_der: bytes,
    ) -> VerifyResult:
        """Verify proof that the client TPM recovered ``seed``.

        In the complete key-attestation flow the client first runs
        ``TPM2_ActivateCredential`` with the verifier-created response blobs.
        If it can recover ``seed``, it signs ``seed`` with the requested key and
        sends that signature as ``KeyAttestPoP``.  This method verifies that PoP.
        """
        try:
            pop = decode_key_attest_pop(pop_der)
        except ValueError as exc:
            return VerifyResult.contraindicated(str(exc))
        if not verify_key_attest_pop(seed=seed, spki_der=spki_der, pop=pop):
            return VerifyResult.contraindicated("KeyAttestPoP signature does not verify over seed")
        return VerifyResult.affirming({"activate_credential_pop": "KeyAttestPoP verified over seed"})


__all__ = [
    "MakeCredentialCallback",
    "TpmActivationChallenge",
    "TpmKeyAttestVerifier",
]
