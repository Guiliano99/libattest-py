# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""SE05x key attestation, end to end against the simulator, in one process.

The RA (Relying Party), the verifier and the Attester all run here; only the SE is
remote. The flow:

1. The RA issues a 16-byte nonce for the ``se05x-attest-request`` type.
2. The Attester generates a P-256 key inside the SE and reads it with attestation,
   the nonce unchanged as the SE's freshness value, then packs the Evidence and the
   attestation certificate (``0xF0000013``) into an ``AttestationBundle``.
3. The RA's engine routes the statement through ``se05x_profile`` to the in-process
   :class:`~libattest.verifier.se05x.Se05xAttestVerifier`, passing the SE key's
   SubjectPublicKeyInfo as the to-be-certified key; the verifier issues an EAR and the
   RA's ``EarAcceptancePolicy`` checks it against the verifier's pinned key.
4. The same bundle, replayed under a new nonce, is refused.
5. The SE key signs a digest, the primitive a CSR's proof of possession uses.

Run ``provision.py`` first: it certifies the SE's attestation key under a demo root and
writes that root to ``$TRUST_DIR/root.pem``.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from pyasn1.type import univ

from libattest import get_nonce_request_oid_for_name
from libattest.asn1_utils import encode_to_der
from libattest.attester.se05x_client import Se05xAttestProvider, Se05xClient, Se05xError
from libattest.formats.csrattest import (
    pem_chain_to_cmp_certs,
    prepare_asn1_attestation_statement,
    prepare_attestation_bundle,
)
from libattest.formats.eat_ear import cwt_jwt_utils
from libattest.formats.se05x import apdu
from libattest.formats.se05x.structures import decode_se05x_attest_evidence
from libattest.ra import EarAcceptancePolicy, NonceStore, ProfileRegistry, RemoteAttestationEngine, se05x_profile
from libattest.ra.engine import BundleVerifyOutcome
from libattest.verifier.se05x import Se05xAttestVerifier

#: ``ear.appraisal-policy-id``: names the trust-anchor class, so a demo EAR never looks NXP-rooted.
POLICY_ID = "policy:SE05X/demo-sim-root"
#: The key the demo generates in the SE and attests: the key a CSR would certify.
SUBJECT_KEY_ID = 0x10AA0002
#: Its policy: usable for CSR signing, readable, deletable; no ATTESTATION (it is attested, not attesting).
SUBJECT_KEY_POLICY = (
    apdu.POLICY_ALLOW_READ | apdu.POLICY_ALLOW_SIGN | apdu.POLICY_ALLOW_VERIFY | apdu.POLICY_ALLOW_DELETE
)
REQUEST_OID = get_nonce_request_oid_for_name("se05x-attest-request")
_SW_CONDITIONS_NOT_SATISFIED = 0x6985  # what the simulator answers for a missing object


def make_engine(root: x509.Certificate) -> tuple[RemoteAttestationEngine, Se05xAttestVerifier]:
    """Return an RA engine that serves SE05x attesters, and its in-process verifier."""
    verifier = Se05xAttestVerifier(roots=[root], policy_id=POLICY_ID)
    profiles = ProfileRegistry()
    profiles.register(se05x_profile(verifier=verifier))
    # 16 bytes: the SE signs the nonce unchanged as its freshness, which is exactly 16 bytes.
    # No anchors: the profile pins the verifier's own EAR key.
    engine = RemoteAttestationEngine(profiles, NonceStore(nonce_bytes=16), ear_policy=EarAcceptancePolicy())
    return engine, verifier


def issue_nonce(engine: RemoteAttestationEngine, tx_id: bytes) -> bytes:
    """Return a new RA nonce for the SE05x request type under *tx_id*."""
    return bytes(engine.build_nonce_response(tx_id, REQUEST_OID)["nonce"])


def _spki(point: bytes) -> bytes:
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def attest(se: Se05xClient, nonce: bytes) -> tuple[bytes, bytes]:
    """Generate the subject key in the SE and attest it under *nonce*.

    Returns
    -------
    tuple[bytes, bytes]
        ``(AttestationBundle DER, subject key SubjectPublicKeyInfo DER)``.

    """
    try:
        se.delete_object(SUBJECT_KEY_ID)
    except Se05xError as exc:
        if exc.sw != _SW_CONDITIONS_NOT_SATISFIED:
            raise
    se.generate_ec_key(SUBJECT_KEY_ID, policy=SUBJECT_KEY_POLICY)
    spki = _spki(se.read_object(SUBJECT_KEY_ID))
    print(f"  generated P-256 key 0x{SUBJECT_KEY_ID:08X} inside the SE (policy READ|SIGN|VERIFY|DELETE)")

    leaf = x509.load_der_x509_certificate(se.read_object(apdu.CERT_OBJECT_ID))
    chain_pem = leaf.public_bytes(serialization.Encoding.PEM).decode("ascii")
    print(f"  attestation certificate from 0x{apdu.CERT_OBJECT_ID:08X}: {leaf.subject.rfc4514_string()}")

    result = Se05xAttestProvider(se, key_id=SUBJECT_KEY_ID, cert_chain_pem=chain_pem).generate_evidence(nonce)
    evidence = decode_se05x_attest_evidence(result.evidence_bytes())
    command = apdu.parse_attested_read_command(bytes(evidence["commandApdu"]))
    response = apdu.parse_attested_read_response(bytes(evidence["responseBody"]))
    origin = apdu.parse_attributes(response.attributes).origin
    print(f"  attested read signed by 0x{command.attest_key_id:08X}: freshness (TAG_7) {command.freshness.hex()}")
    print(f"    key origin 0x{origin:02X} (0x02 = generated inside the SE), chip id {response.chip_id.hex().upper()}")

    statement = prepare_asn1_attestation_statement(univ.ObjectIdentifier(result.oid), result.evidence_bytes())
    bundle = encode_to_der(prepare_attestation_bundle([statement], certs=pem_chain_to_cmp_certs(chain_pem)))
    return bundle, spki


def verdict(outcome: BundleVerifyOutcome) -> str:
    """Return ``ACCEPT`` or ``REJECT: <reasons>`` for *outcome*."""
    failure = outcome.first_failure
    return "ACCEPT" if outcome.accepted else "REJECT: " + ("; ".join(failure.errors) if failure else "?")


def run_demo(host: str, port: int, trust_dir: Path) -> bool:
    """Run the flow against the SE at *host*:*port*; return whether it behaved as it must.

    ``True`` only if the fresh bundle was accepted with an affirming EAR and its replay
    was refused.
    """
    root = x509.load_pem_x509_certificate((trust_dir / "root.pem").read_bytes())
    engine, verifier = make_engine(root)
    print(f"RA trust anchor for SE05x attestation: {root.subject.rfc4514_string()}")

    tx_id = os.urandom(16)
    print("\n[1] RA issues a nonce")
    nonce = issue_nonce(engine, tx_id)
    print(f"  {len(nonce)}-byte nonce {nonce.hex()}")

    with Se05xClient(host, port) as se:
        se.select()
        print("\n[2] Attester: generate the key in the SE and attest it")
        bundle, spki = attest(se, nonce)
        print(f"  AttestationBundle: {len(bundle)} bytes")

        print("\n[3] RA verifies the bundle, binding it to the CSR key (the SE key's SPKI)")
        outcome = engine.verify_bundle(bundle, tx_id, pubkey=spki)
        print(f"  verdict: {verdict(outcome)}")
        if outcome.accepted and outcome.first_ear is not None:
            claims = cwt_jwt_utils.verify_es256(outcome.first_ear, verifier.ear_verification_pem())
            submod = claims["submods"]["SE05X"]
            ear_nonce = cwt_jwt_utils.b64u_decode(claims["eat_nonce"])
            print(f"  EAR by {claims['ear.verifier-id']['developer']}, submod SE05X:")
            print(f"    ear.status                 {submod['ear.status']}")
            print(f"    ear.trustworthiness-vector {submod['ear.trustworthiness-vector']}")
            print("      instance-identity 2: recognized (certified under the configured root), not known compromised")
            print(f"    ear.appraisal-policy-id    {submod['ear.appraisal-policy-id']}")
            print(f"    eat_nonce                  {ear_nonce.hex()} (equals the RA nonce: {ear_nonce == nonce})")

        print("\n[4] Replay: the same bundle under a new nonce of the same transaction")
        issue_nonce(engine, tx_id)
        replay = engine.verify_bundle(bundle, tx_id, pubkey=spki)
        print(f"  verdict: {verdict(replay)}")

        print("\n[5] The SE key signs a digest (a CSR's proof of possession)")
        digest = hashlib.sha256(b"CertificationRequestInfo of the CSR").digest()
        signature = se.sign_digest(SUBJECT_KEY_ID, digest)
        subject_key = serialization.load_der_public_key(spki)
        assert isinstance(subject_key, ec.EllipticCurvePublicKey)
        subject_key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        print(f"  {len(signature)}-byte ECDSA signature verifies with the attested key")

    ok = outcome.accepted and not replay.accepted
    print(
        "\nOK: fresh Evidence accepted, replay refused"
        if ok
        else "\nFAILED: expected fresh Evidence accepted, replay refused"
    )
    return ok


if __name__ == "__main__":
    sys.exit(
        0
        if run_demo(
            os.environ.get("SE05X_HOST", "127.0.0.1"),
            int(os.environ.get("SE05X_PORT", "8050")),
            Path(os.environ.get("TRUST_DIR", "trust")),
        )
        else 1
    )
