# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Device-side EK provisioning for the credential-activation demo.

Provisions a real Endorsement Key on the TPM and writes the two artifacts the
verifier needs:

* ``ek_tpm2b_public_key.raw`` — the marshalled ``TPM2B_PUBLIC`` (nameAlg,
  objectAttributes, symmetric params, unique).  This is what software
  ``TPM2_MakeCredential`` consumes — a certificate alone is not enough.
* ``ek_cert_chain.pem`` — a demo EK certificate whose subject public key is the
  EK.  A genuine EK is decrypt-only and cannot sign, and the IBM simulator ships
  no manufacturer EK cert, so this leaf is signed by an ephemeral demo issuer
  key purely to produce a valid X.509 structure.  The verifier uses TOFU and
  checks only that the cert's key equals the TPM2B_PUBLIC — the signature is
  never validated.

Run standalone (writes into ``--out-dir``) or import :func:`provision` from the
end-to-end demo, which keeps the live ``TpmClient`` to run ActivateCredential.
"""

from __future__ import annotations

import argparse
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key
from cryptography.x509.oid import NameOID
from tpm2_pytss import TPM2B_PUBLIC


def mint_demo_ek_cert(ek_public: TPM2B_PUBLIC) -> bytes:
    """Return a PEM demo EK certificate carrying ``ek_public`` as its subject key.

    Signed by a throwaway P-256 issuer key (see module docstring for why the EK
    itself cannot self-sign).
    """
    ek_pubkey = load_der_public_key(ek_public.to_der())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-EK")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo-EK-issuer")]))
        .public_key(ek_pubkey)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(issuer_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def write_artifacts(out_dir: str, ek_public: TPM2B_PUBLIC) -> tuple[str, str]:
    """Write ``ek_tpm2b_public_key.raw`` and ``ek_cert_chain.pem`` into ``out_dir``.

    Returns the two paths.
    """
    os.makedirs(out_dir, exist_ok=True)
    raw_path = os.path.join(out_dir, "ek_tpm2b_public_key.raw")
    pem_path = os.path.join(out_dir, "ek_cert_chain.pem")
    with open(raw_path, "wb") as fh:
        fh.write(bytes(ek_public.marshal()))
    with open(pem_path, "wb") as fh:
        fh.write(mint_demo_ek_cert(ek_public))
    return raw_path, pem_path


def provision(out_dir: str, tcti: str | None = None):
    """Provision EK + AK on the TPM, write artifacts, return ``(tpm, ak_name, paths)``.

    The caller owns the returned live ``TpmClient`` (still connected) so it can
    run ``TPM2_ActivateCredential``; close it when done.
    """
    from libattest.attester.tpm_client import TpmClient

    resolved = tcti or os.environ.get("TCTI", "libtpms:")
    tpm = TpmClient(tcti=resolved).connect()
    tpm.provision_ek()
    _ak_public, ak_name = tpm.provision_ak()
    paths = write_artifacts(out_dir, tpm.ek_public)
    return tpm, bytes(ak_name), paths


def main() -> None:
    """Provision and write the EK artifacts, then exit (device-only step)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default="ek-artifacts", help="where to write EK artifacts")
    parser.add_argument("--tcti", default=None, help="TPM TCTI (default: $TCTI or libtpms:)")
    args = parser.parse_args()

    tpm, _ak_name, (raw_path, pem_path) = provision(args.out_dir, args.tcti)
    tpm.close()
    print(f"wrote {raw_path}")
    print(f"wrote {pem_path}")


if __name__ == "__main__":
    main()
