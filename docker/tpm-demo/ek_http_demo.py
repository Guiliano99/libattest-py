# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""End-to-end EK credential-activation demo over a real HTTP boundary.

Ties the pieces together:

1. **Device** provisions its EK (real TPM) and writes ``ek_tpm2b_public_key.raw``
   + ``ek_cert_chain.pem`` (:mod:`provision_ek`).
2. **Device → Verifier** ``POST /demo/ek/submit`` — the verifier bind-checks the
   cert against the TPM2B_PUBLIC and stores the mapping, returning an ``ek_id``.
3. **Device → Verifier** ``POST /demo/ek/challenge`` — the verifier looks the EK
   public area up by ``ek_id``, runs software ``TPM2_MakeCredential`` over
   ``(EK, AK Name)``, and returns the two blobs (seed retained server-side).
4. **Device** runs ``TPM2_ActivateCredential`` to recover the seed, then
   ``POST /demo/ek/verify-seed`` with ``H(seed)`` — only a TPM holding both the
   EK and the named AK can produce it.

The verifier runs as a stdlib ``HTTPServer`` in a background thread, so the HTTP
round trip is genuine (loopback). A real TPM is required for the device side;
use the docker stack (``TCTI=mssim:host=tpmsim,port=2321``).
"""

from __future__ import annotations

import contextlib
import os
import socket
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ek_http_verifier import serve_in_thread  # noqa: E402
from provision_ek import provision  # noqa: E402

from attest_client import AttestClient, AttestClientConfig  # noqa: E402
from libattest.verifier.ek_store import EkStore  # noqa: E402


def _free_port() -> int:
    """Return an OS-assigned free TCP port on loopback."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_demo(tcti: str | None = None) -> bool:
    """Run provision → submit → challenge → activate → verify; return the verdict.

    ``True`` iff the verifier confirms the device recovered exactly the seed it
    wrapped to ``(EK, AK Name)``.
    """
    resolved_tcti = tcti or os.environ.get("TCTI", "libtpms:")
    port = _free_port()
    server = serve_in_thread(EkStore(), port=port)

    try:
        with tempfile.TemporaryDirectory() as out_dir:
            tpm, ak_name, (raw_path, pem_path) = provision(out_dir, resolved_tcti)
            try:
                with open(raw_path, "rb") as fh:
                    ek_raw = fh.read()
                with open(pem_path, "rb") as fh:
                    ek_chain = fh.read()

                client = AttestClient(AttestClientConfig(host="127.0.0.1", verification_port=port))
                with client:
                    ek_id = client.submit_ek(ek_chain, ek_raw)
                    session_id, enc_secret, enc_seed = client.request_credential_challenge(ek_id, ak_name)
                    seed = tpm.recover_seed(enc_secret=enc_secret, enc_seed=enc_seed)
                    accepted = client.report_seed(session_id, seed)
            finally:
                tpm.close()
    finally:
        server.shutdown()

    print("EK credential-activation demo (HTTP submit + lookup)")
    print(f"TCTI:              {resolved_tcti}")
    print(f"verifier port:     {port}")
    print(f"ek_id:             {ek_id}")
    print(f"seed recovered:    {seed.hex()}")
    print(f"verifier accepted: {accepted}")
    print(f"Verdict:           {'ACCEPT' if accepted else 'REJECT'}")
    return accepted


def main() -> None:
    """Run the HTTP EK demo as a script."""
    raise SystemExit(0 if run_demo() else 1)


if __name__ == "__main__":
    main()
