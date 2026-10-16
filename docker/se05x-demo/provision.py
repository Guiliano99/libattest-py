# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Give the simulated SE05x an attestation certificate (the compose ``provision`` service).

A real SE05x leaves NXP's factory with a certificate for its attestation key. The
simulator draws a new attestation key at every start and has none, so this script
plays the manufacturer, once per simulator start:

1. read the attestation public key (``0xF0000012``) and the chip id (``0x7FFF0206``);
2. mint an ephemeral demo root CA and, under it, a certificate for that key;
3. store the DER certificate in the SE as the binary file ``0xF0000013``;
4. write only the root certificate to ``$TRUST_DIR/root.pem``, the verifier's trust anchor.

The root private key exists only in this process's memory and dies with it. Running
the script again against the same simulator mints a new root and replaces both the
certificate and ``root.pem``.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from libattest.attester.se05x_client import Se05xClient, Se05xError
from libattest.formats.se05x.apdu import ATTEST_KEY_ID, CERT_OBJECT_ID, UNIQUE_ID_OBJECT_ID

ROOT_NAME = "libattest demo SE05x attestation root (not NXP)"
_VALIDITY = datetime.timedelta(days=3 * 365)
_SW_CONDITIONS_NOT_SATISFIED = 0x6985  # what the simulator answers for a missing object


def _key_usage(*, digital_signature: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def mint_certificates(
    attest_key: ec.EllipticCurvePublicKey, chip_id: bytes
) -> tuple[x509.Certificate, x509.Certificate]:
    """Return ``(root, leaf)``: a new demo root CA and its certificate for *attest_key*.

    The leaf's subject carries the chip id in hex as its ``serialNumber``. The root's
    private key is not returned.
    """
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ROOT_NAME)])
    now = datetime.datetime.now(datetime.UTC)
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    leaf_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "SE05x attestation key"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, chip_id.hex().upper()),
        ]
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(attest_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + _VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(attest_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    return root, leaf


def provision(host: str, port: int, trust_dir: Path) -> None:
    """Certify the SE's attestation key under a new demo root; write the root to *trust_dir*."""
    with Se05xClient(host, port) as se:
        se.select()
        point = se.read_object(ATTEST_KEY_ID)
        chip_id = se.read_object(UNIQUE_ID_OBJECT_ID)
        print(f"SE at {host}:{port}, chip id {chip_id.hex().upper()}")
        print(f"  attestation key 0x{ATTEST_KEY_ID:08X}: {point.hex()[:24]}... (P-256)")

        root, leaf = mint_certificates(ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point), chip_id)
        print(f"  minted an ephemeral root: {root.subject.rfc4514_string()}")
        print(f"  and under it:             {leaf.subject.rfc4514_string()}")

        try:
            se.delete_object(CERT_OBJECT_ID)
            print(f"  replaced the previous certificate in 0x{CERT_OBJECT_ID:08X}")
        except Se05xError as exc:
            if exc.sw != _SW_CONDITIONS_NOT_SATISFIED:
                raise
        der = leaf.public_bytes(serialization.Encoding.DER)
        se.write_binary(CERT_OBJECT_ID, der)
        print(f"  stored the attestation certificate in 0x{CERT_OBJECT_ID:08X} ({len(der)} bytes)")

    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print(f"  wrote the root certificate to {trust_dir / 'root.pem'}; its private key is discarded")


if __name__ == "__main__":
    provision(
        os.environ.get("SE05X_HOST", "127.0.0.1"),
        int(os.environ.get("SE05X_PORT", "8050")),
        Path(os.environ.get("TRUST_DIR", "trust")),
    )
