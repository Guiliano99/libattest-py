# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Demo verifier HTTP surface for the EK credential-activation flow.

A stdlib ``http.server`` app over :class:`libattest.verifier.ek_store.EkStore`.
All the cryptography (bind check, software MakeCredential, seed retention) lives
in the library; this file is just JSON/base64 plumbing plus a threaded server
for the self-contained demo/test.  Kept on the standard library on purpose — the
minimal TPM client image ships no web framework.  Three routes:

* ``POST /demo/ek/submit``      — store EK cert chain + TPM2B_PUBLIC → ``ek_id``
* ``POST /demo/ek/challenge``   — MakeCredential over ``(ek_id, ak_name)``
* ``POST /demo/ek/verify-seed`` — confirm the device recovered the seed
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from libattest.verifier.ek_store import EkStore


def _make_handler(store: EkStore):
    """Build a request handler class bound to ``store``."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args) -> None:  # noqa: A002, D401 - silence access log
            """Suppress the default stderr access log."""

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            length = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"detail": "invalid JSON body"})
                return
            try:
                if self.path == "/demo/ek/submit":
                    ek_id = store.submit(
                        req["ek_cert_chain_pem"].encode("ascii"),
                        base64.b64decode(req["ek_tpm2b_public_b64"]),
                    )
                    self._send(200, {"ek_id": ek_id})
                elif self.path == "/demo/ek/challenge":
                    ek_id, ak_name = req["ek_id"], base64.b64decode(req["ak_name_b64"])
                    try:
                        session_id, enc_seed, enc_secret = store.make_challenge(ek_id, ak_name)
                    except KeyError:  # unknown ek_id — distinct from a missing field
                        self._send(404, {"detail": f"unknown ek_id {ek_id}"})
                        return
                    self._send(
                        200,
                        {
                            "session_id": session_id,
                            "enc_seed_b64": base64.b64encode(enc_seed).decode("ascii"),
                            "enc_secret_b64": base64.b64encode(enc_secret).decode("ascii"),
                        },
                    )
                elif self.path == "/demo/ek/verify-seed":
                    accepted = store.verify_seed(req["session_id"], req["seed_sha256"])
                    self._send(200, {"accepted": accepted})
                else:
                    self._send(404, {"detail": f"unknown path {self.path}"})
            except KeyError as exc:  # missing request field
                self._send(400, {"detail": f"missing field {exc}"})
            except ValueError as exc:  # bind-check failure / bad chain / bad base64
                self._send(400, {"detail": str(exc)})

    return _Handler


def serve_in_thread(store: EkStore, host: str = "127.0.0.1", port: int = 8080) -> HTTPServer:
    """Start a single-threaded HTTP server bound to ``store``; return it.

    Runs its ``serve_forever`` loop in a daemon thread so the demo/test exercises
    a genuine loopback HTTP round trip.  Single-threaded on purpose: ``EkStore``
    is not thread-safe and the demo client is sequential.  Stop it with
    ``server.shutdown()``.
    """
    server = HTTPServer((host, port), _make_handler(store))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
