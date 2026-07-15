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
  (:func:`libattest.formats.eat_ear.cwt_jwt.verify_ear_jwt`), and
* checks the EAR verdict is affirming (:func:`libattest.formats.eat_ear.cwt_jwt.ear_is_affirming`).

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
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.eat_ear.cwt_jwt import ear_is_affirming, verify_ear_jwt
from libattest.types import VerifyResult
from libattest.verifier.base import AttestationVerifier

logger = logging.getLogger(__name__)

DEFAULT_SUBMIT_PATH = os.environ.get("VERIFIER_SUBMIT_PATH") or "/submitEvidenceCMP"
DEFAULT_EAR_KEY_PATH = "/ear-verification-key"
DEFAULT_MAKECRED_PATH = os.environ.get("VERIFIER_MAKECRED_PATH") or "/makeCredential"

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
            return VerifyResult.contraindicated(f"verifier {self.base_url} rejected the evidence")
        return VerifyResult.affirming(ear_jwt)

    # ── /submitEvidenceCMP ─────────────────────────────────────────────────────

    def submit_evidence(
        self,
        nonce: bytes,
        evidence: bytes,
        evidence_oid: str | None = None,
        resp_info_json: dict | None = None,
        *,
        session_id: str | None = None,
        pubkey: bytes | None = None,
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
            Optional plain-JSON ``NonceResponse.respTypeInfo.respInfo`` (not
            base64/DER), forwarded so the verifier can confirm negotiated
            parameters (e.g. the requested PCR set + hash algorithm for the TPM
            profile).
        session_id:
            Optional verifier session id (key-attestation profile only); echoed
            so the verifier can find the retained activation seed.
        pubkey:
            Optional to-be-certified SubjectPublicKeyInfo DER (key-attestation
            profile only, base64-encoded on the wire); the verifier matches it
            against the certified TPM key.

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
        if session_id is not None:
            body["sessionId"] = session_id
        if pubkey is not None:
            body["pubkey"] = base64.b64encode(pubkey).decode("ascii")

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
        except requests.RequestException as exc:
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
                "VeraisonVerifierClient: no EAR signing key available from %s — rejecting evidence (fail closed)",
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

    # ── /makeCredential (key-attestation challenge) ────────────────────────────

    def make_credential(
        self,
        ak_name: str,
        ek_public: str,
        ek_cert_chain_pem: str,
        *,
        path: str = DEFAULT_MAKECRED_PATH,
    ) -> dict:
        """POST a decomposed ``KeyAttestChall`` and return the verifier's reply.

        Runs the verifier's software ``TPM2_MakeCredential`` (the key-attestation
        nonce leg).  Unlike :meth:`submit_evidence`, this is **fail-loud**: the
        challenge is mandatory to the flow, so a transport/JSON error raises
        rather than returning a soft ``None`` (there is no verdict to degrade to).

        Parameters
        ----------
        ak_name, ek_public:
            Hex-encoded AK Name and marshalled EK ``TPM2B_PUBLIC`` from the client
            ``KeyAttestChall`` (decoded by the RA adapter).
        ek_cert_chain_pem:
            The client EK certificate chain (PEM) — registration context.
        path:
            Endpoint path appended to the base URL (default ``/makeCredential``).

        Returns
        -------
        dict
            The verifier reply ``{sessionId, encSeed, encSecret}``.

        Raises
        ------
        requests.RequestException
            On any HTTP transport error or non-2xx status.
        ValueError
            When the reply is not JSON or is missing a required field.

        """
        url = f"{self.base_url}{path}"
        body = {"akName": ak_name, "ekPublic": ek_public, "ekCertChain": ek_cert_chain_pem}
        logger.info(
            "VeraisonVerifierClient.make_credential: POST %s (akName=%d hex chars, ekPublic=%d hex chars)",
            url,
            len(ak_name),
            len(ek_public),
        )
        if _LOG_PAYLOAD:
            logger.info("VeraisonVerifierClient.make_credential: JSON body to %s: %s", url, json.dumps(body))

        resp = requests.post(
            url,
            json=body,
            timeout=self.fetch_timeout,
            verify=self.tls_verify,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as exc:
            raise ValueError(f"make_credential: non-JSON reply from {url}: {exc}") from exc
        for field_name in ("sessionId", "encSeed", "encSecret"):
            if field_name not in data:
                raise ValueError(f"make_credential reply from {url} missing '{field_name}'")
        logger.info(
            "VeraisonVerifierClient.make_credential: sessionId=%s encSeed=%d hex chars encSecret=%d hex chars",
            data["sessionId"],
            len(data["encSeed"]),
            len(data["encSecret"]),
        )
        return data

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
        except (requests.RequestException, ValueError, UnsupportedAlgorithm) as exc:
            # Transport error, un-decodable PEM, or an unsupported key type all
            # mean we cannot authenticate the verdict -> fail closed (return None).
            # A genuine programming bug (other exception types) is left to propagate.
            logger.warning("VeraisonVerifierClient: could not fetch EAR signing public key from %s: %s", url, exc)
            return None


__all__ = [
    "DEFAULT_EAR_KEY_PATH",
    "DEFAULT_MAKECRED_PATH",
    "DEFAULT_SUBMIT_PATH",
    "VeraisonVerifierClient",
]
