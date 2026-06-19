# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP verifier client implementing the :class:`AttestationVerifier` seam.

:class:`VeraisonVerifierClient` is the default verifier the RA engine talks to.
It is the ``/submitEvidenceCMP`` → EAR client moved out of the MockCA
(``remote_att_mockca/attestation_verifier.py``): a per-base-URL HTTP client that

* POSTs ``{nonce, evidence, oid?, resp_info_json?}`` to ``/submitEvidenceCMP``
  and reads back ``{"ear": "<EAR JWT>"}``,
* fetches and caches the verifier's EAR signing key from
  ``/ear-verification-key`` and verifies every EAR JWT signature
  (:func:`libattest.ear.verify_ear_jwt`), and
* checks the EAR verdict is affirming (:func:`libattest.ear.ear_is_affirming`).

It implements the :class:`~libattest.verifier.base.AttestationVerifier` ABC
(``get_nonce`` / ``verify_token``) so the engine and the
:class:`~libattest.ra.registry.ServiceRegistry` treat it like any other
verifier — a developer swaps it for a custom verifier by registration, with no
engine edit.  Under the RA-issued-nonce model the RA owns nonce generation, so
``get_nonce`` returns empty bytes (no nonce is fetched from the verifier).

The submit path is configurable via ``VERIFIER_SUBMIT_PATH`` so one example can
target a distinct endpoint; ``VERIFIER_LOG_PAYLOAD=1`` logs the exact JSON body.
"""

from __future__ import annotations

import base64
import json
import logging
import os

import requests
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.ear import ear_is_affirming, verify_ear_jwt
from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier

logger = logging.getLogger(__name__)

DEFAULT_SUBMIT_PATH = os.environ.get("VERIFIER_SUBMIT_PATH") or "/submitEvidenceCMP"
DEFAULT_EAR_KEY_PATH = "/ear-verification-key"

_LOG_PAYLOAD = (os.environ.get("VERIFIER_LOG_PAYLOAD") or "").strip().lower() in (
    "1",
    "true",
    "yes",
)


class VeraisonVerifierClient(AttestationVerifier):
    """HTTP client for a single Veraison verifier endpoint (one base URL).

    Parameters
    ----------
    base_url:
        Base URL of the verifier (trailing slash stripped); the canonical
        paths are appended per call (e.g. ``http://tpm-verifier:8444``).
    submit_path:
        Path of the evidence-submission endpoint.  Defaults to
        :data:`DEFAULT_SUBMIT_PATH` (env-overridable via
        ``VERIFIER_SUBMIT_PATH``).
    ear_key_path:
        Path of the EAR signing-key endpoint.  Defaults to
        :data:`DEFAULT_EAR_KEY_PATH`.
    tls_verify:
        Whether to verify HTTPS certificates.  Defaults to ``True`` (secure by
        default for reuse).  The demo's plain-HTTP intra-compose traffic ignores
        it (``verify`` is moot for non-TLS URLs); callers using ``https://`` with
        a self-signed verifier must opt out explicitly (``tls_verify=False``).
    fetch_timeout:
        Per-request timeout in seconds.
    media_type:
        Default media type reported to the engine / router for this verifier.

    """

    def __init__(
        self,
        base_url: str,
        *,
        submit_path: str = DEFAULT_SUBMIT_PATH,
        ear_key_path: str = DEFAULT_EAR_KEY_PATH,
        tls_verify: bool = True,
        fetch_timeout: int = 10,
        media_type: str = "application/octet-stream",
    ) -> None:
        """Configure the client for a single verifier base URL."""
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.submit_path = submit_path
        self.ear_key_path = ear_key_path
        self.tls_verify = tls_verify
        self.fetch_timeout = fetch_timeout
        self.media_type = media_type
        self._ear_public_key: ec.EllipticCurvePublicKey | None = None
        logger.info("VeraisonVerifierClient initialised: base_url=%s", self.base_url)

    # ── AttestationVerifier interface ──────────────────────────────────────────

    def get_nonce(self, nonce_size: int = 32) -> bytes:
        """Return empty bytes — the RA owns nonce generation, not the verifier."""
        return b""

    def verify_token(
        self,
        token_bytes: bytes,
        media_type: str,
        nonce: bytes | None = None,
    ) -> VerifyResult:
        """Submit *token_bytes* with *nonce* and return a typed verdict.

        Wraps :meth:`submit_evidence` to satisfy the
        :class:`AttestationVerifier` ABC.  An affirming, signature-verified EAR
        JWT yields :meth:`VerifyResult.affirming` carrying the JWT as payload;
        any rejection (HTTP error, bad signature, non-affirming verdict) yields
        :meth:`VerifyResult.contraindicated`.
        """
        ear_jwt = self.submit_evidence(nonce or b"", token_bytes)
        if ear_jwt is None:
            return VerifyResult.contraindicated(
                f"verifier {self.base_url} rejected the evidence"
            )
        return VerifyResult.affirming(ear_jwt)

    # ── /submitEvidenceCMP ─────────────────────────────────────────────────────

    def submit_evidence(
        self,
        nonce: bytes,
        evidence: bytes,
        evidence_oid: str | None = None,
        resp_info_json: dict | None = None,
    ) -> str | None:
        """POST ``(nonce, evidence)`` to ``{base_url}{submit_path}``.

        Parameters
        ----------
        nonce:
            The RA-issued nonce bound to this evidence (raw bytes; base64-encoded
            on the wire).
        evidence:
            DER-encoded evidence bytes (an ``AttestationStatement`` / bundle, or
            opaque JWT bytes).
        evidence_oid:
            Optional dot-form OID of the evidence type, forwarded so the verifier
            can pick a backend without re-parsing.
        resp_info_json:
            Optional plain-JSON ``NonceResponse.respInfo`` (not base64/DER),
            forwarded so the verifier can confirm negotiated parameters
            (e.g. the requested PCR set + hash algorithm for the TPM profile).

        Returns
        -------
        str | None
            The EAR JWT on success; ``None`` if the verifier rejected the
            evidence (HTTP error, contraindicated verdict, or invalid EAR
            signature).

        """
        url = f"{self.base_url}{self.submit_path}"
        body: dict = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "evidence": base64.b64encode(evidence).decode("ascii"),
        }
        if evidence_oid:
            body["oid"] = evidence_oid
        if resp_info_json is not None:
            body["resp_info_json"] = resp_info_json

        logger.info(
            "VeraisonVerifierClient.submit_evidence: POST %s (oid=%s, evidence=%dB, nonce=%dB%s)",
            url,
            evidence_oid or "<none>",
            len(evidence),
            len(nonce),
            f", resp_info_json={resp_info_json}" if resp_info_json is not None else "",
        )
        if _LOG_PAYLOAD:
            logger.info("VeraisonVerifierClient.submit_evidence: JSON body to %s: %s", url, json.dumps(body))

        try:
            resp = requests.post(
                url,
                json=body,
                timeout=self.fetch_timeout,
                verify=self.tls_verify,
                headers={"Accept": "application/json"},
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("VeraisonVerifierClient: HTTP error to %s: %s", url, exc)
            return None

        if not resp.ok:
            logger.warning("VeraisonVerifierClient: %s returned %d: %s", url, resp.status_code, resp.text[:200])
            return None

        try:
            data = resp.json()
        except ValueError as exc:
            logger.warning("VeraisonVerifierClient: non-JSON response from %s: %s", url, exc)
            return None

        ear_jwt = data.get("ear")
        if not ear_jwt:
            logger.warning("VeraisonVerifierClient: response missing 'ear' field: %s", str(data)[:200])
            return None

        # Fail closed: a missing EAR signing key means we cannot authenticate the
        # verdict, so the evidence MUST be rejected — never accept an unverified
        # (potentially forged/unsigned) EAR.
        pub_key = self._fetch_ear_public_key()
        if pub_key is None:
            logger.error(
                "VeraisonVerifierClient: no EAR signing key available from %s "
                "— rejecting evidence (fail closed)",
                self.base_url,
            )
            return None
        if not verify_ear_jwt(ear_jwt, pub_key):
            logger.warning("VeraisonVerifierClient: EAR JWT signature verification FAILED — rejecting")
            return None
        logger.info("VeraisonVerifierClient: EAR JWT signature verified OK")

        if not ear_is_affirming(ear_jwt):
            logger.warning("VeraisonVerifierClient: EAR verdict is NOT affirming — rejecting")
            return None

        return ear_jwt

    # ── /ear-verification-key (cached) ─────────────────────────────────────────

    def _fetch_ear_public_key(self) -> ec.EllipticCurvePublicKey | None:
        """Lazily fetch and cache ``GET {base_url}{ear_key_path}``."""
        if self._ear_public_key is not None:
            return self._ear_public_key

        url = f"{self.base_url}{self.ear_key_path}"
        try:
            resp = requests.get(url, timeout=self.fetch_timeout, verify=self.tls_verify)
            resp.raise_for_status()
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            key = load_pem_public_key(resp.content)
            if not isinstance(key, ec.EllipticCurvePublicKey):
                logger.warning("VeraisonVerifierClient: EAR key from %s is not an EC key — skipping verification", url)
                return None
            self._ear_public_key = key
            return key
        except Exception as exc:  # noqa: BLE001
            logger.warning("VeraisonVerifierClient: could not fetch EAR signing public key from %s: %s", url, exc)
            return None


__all__ = [
    "DEFAULT_EAR_KEY_PATH",
    "DEFAULT_SUBMIT_PATH",
    "VeraisonVerifierClient",
]
