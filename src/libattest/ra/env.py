# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Environment-variable wiring for a deployment's :class:`~libattest.ra.ProfileRegistry`.

Moved here from the MockCA's ``attestation_routes.py`` / ``verifier_registry.py``:
building a ``ProfileRegistry`` from env vars is RA orchestration, not a CMP
carrier concern, and libattest already reads env vars for OID defaults and
verifier paths (see the ``TPM_PCR_SELECTION_OID`` / ``EAR_OID`` /
``KEY_ATTEST_EVIDENCE_OID`` resolvers) — this keeps deployment wiring in one
place instead of two.

Env vars consumed
------------------
``VERIFIER_OID_ROUTES``    JSON map ``{"<oid-dot>": "<url>", ...}`` — evidence-
                           type OID -> verifier URL. Empty/unset is allowed if
                           a fallback is set.
``VERIFIER_URL_FALLBACK``  Default URL used when the OID lookup does not
                           resolve.
``TPM_QUOTE_PCRS``         PCR set the quote profile broadcasts in respInfo
                           (comma-separated ints; default ``"0,1,2,3,4"``).
``TPM_PCR_SELECTION_OID``  Quote-leg request-type OID (also read by
                           ``libattest.formats.tpm.quote_profile`` at import
                           time; re-read here so a call-time override — e.g.
                           in a test fixture — still takes effect for routing).
``TPM_KEY_ATTEST_OID``     Certify-leg request-type OID.
``EAR_OID``                EAR-extension OID (raw JWT, or id-pe-cmw for CMW).

At least one of ``VERIFIER_OID_ROUTES`` / ``VERIFIER_URL_FALLBACK`` must
resolve a route, or :class:`RuntimeError` is raised — a deployment mistake
surfaces at startup, not at the first GenM.
"""

from __future__ import annotations

import json
import logging
import os

from libattest import get_oid_by_name
from libattest.formats._oid_json import resolve_env_oid
from libattest.formats.ear_extension import EAR_EXTENSION_OID_DEFAULT, EAR_EXTENSION_OID_ENV
from libattest.formats.tpm.quote_profile import TPM_QUOTE_REQ_OID_DEFAULT, TPM_QUOTE_REQ_OID_ENV
from libattest.ra.profile import jwt_profile, key_attest_profile, tpm_profile
from libattest.ra.registry import ProfileRegistry

logger = logging.getLogger(__name__)

_ID_TCG_ATTEST_QUOTE = get_oid_by_name("tcg-attest-quote")
_ID_KEY_ATTEST_EVIDENCE = get_oid_by_name("key-attest")

# The platform demo advertises ak-1 as its first quote certificate-name label.
# The RA/CA selects and returns that label in TPM20QuoteRespInfo.
_TPM_QUOTE_SELECTED_CERTIFICATE_NAME = "ak-1"

#: Certify-leg (key-attestation) request-type OID env var. Matches the
#: gencmpclient C attester's ``TPM_KEY_ATTEST_OID_DEFAULT``.
TPM_KEY_ATTEST_REQUEST_OID_ENV: str = "TPM_KEY_ATTEST_OID"
TPM_KEY_ATTEST_REQUEST_OID_DEFAULT: str = "1.3.6.1.4.1.99999.4"


def _parse_oid_routes_env() -> dict[str, str]:
    """Decode the ``VERIFIER_OID_ROUTES`` JSON env var, with a clear error."""
    raw = os.environ.get("VERIFIER_OID_ROUTES", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"VERIFIER_OID_ROUTES is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("VERIFIER_OID_ROUTES must decode to a JSON object")
    return {str(k): str(v).rstrip("/") for k, v in data.items()}


def _parse_pcr_list_env(value: str) -> list[int]:
    """Parse ``TPM_QUOTE_PCRS`` (e.g. ``"0,1,2,3,4"``) into a list of ints.

    Empty / invalid entries are dropped with a warning; an empty or unparseable
    value falls back to ``[0, 1, 2, 3, 4]`` so a typo never breaks startup.
    """
    fallback = [0, 1, 2, 3, 4]
    if not value:
        return fallback
    out: list[int] = []
    for tok in value.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            n = int(tok)
        except ValueError:
            logger.warning("TPM_QUOTE_PCRS: ignoring non-integer entry %r", tok)
            continue
        if n < 0:
            logger.warning("TPM_QUOTE_PCRS: ignoring negative PCR index %d", n)
            continue
        out.append(n)
    return out or fallback


def build_profile_registry_from_env() -> ProfileRegistry:
    """Build a :class:`ProfileRegistry` from the canonical RA env vars.

    Seeds up to three profiles:

    1. the **TPM platform (quote) profile** — request type
       ``TPM_PCR_SELECTION_OID``, statement ``TcgAttestQuote``;
    2. the **TPM key-attestation (v5) profile** — request type
       ``TPM_KEY_ATTEST_OID``, statement ``KeyAttestEvidence``;
    3. a **``jwt_profile``** for any other OID in ``VERIFIER_OID_ROUTES`` with
       no built-in handler (sw/EAR shapes) — a new opaque-evidence type is
       therefore pure configuration.

    Raises
    ------
    RuntimeError
        Neither ``VERIFIER_OID_ROUTES`` nor ``VERIFIER_URL_FALLBACK`` is
        configured — nothing could ever resolve a verifier URL.

    """
    oid_routes = _parse_oid_routes_env()
    fallback_url = (os.environ.get("VERIFIER_URL_FALLBACK") or "").strip().rstrip("/") or None
    if not (oid_routes or fallback_url):
        raise RuntimeError(
            "build_profile_registry_from_env: refusing to start — no routing configured. "
            "Set at least one of VERIFIER_OID_ROUTES or VERIFIER_URL_FALLBACK."
        )

    def resolve_url(*oids: str | None) -> str | None:
        for oid in oids:
            if oid and oid in oid_routes:
                return oid_routes[oid]
        return fallback_url

    ear_oid = resolve_env_oid(EAR_EXTENSION_OID_ENV, EAR_EXTENSION_OID_DEFAULT)
    pcrs = _parse_pcr_list_env(os.environ.get("TPM_QUOTE_PCRS", "0,1,2,3,4"))
    profiles = ProfileRegistry()

    # 1. TPM platform (quote) profile. request_type = TPM_PCR_SELECTION_OID,
    #    statement = TcgAttestQuote; respInfo broadcasts the PCR set + the
    #    negotiated hash algorithm via the tpm_profile factory. The profile's
    #    response_type_oid (distinct from the request OID) is set by
    #    tpm_profile itself.
    quote_request_oid = resolve_env_oid(TPM_QUOTE_REQ_OID_ENV, TPM_QUOTE_REQ_OID_DEFAULT)
    quote_url = resolve_url(_ID_TCG_ATTEST_QUOTE, quote_request_oid)
    if quote_url:
        profiles.register(
            tpm_profile(
                request_type_oid=quote_request_oid,
                statement_oid=_ID_TCG_ATTEST_QUOTE,
                verifier_url=quote_url,
                pcrs=pcrs,
                certificate_name=_TPM_QUOTE_SELECTED_CERTIFICATE_NAME,
                ear_oid=ear_oid,
            )
        )
    else:
        logger.warning(
            "build_profile_registry_from_env: no verifier URL for the TPM quote profile "
            "(request_type=%s, statement=%s); skipping it",
            quote_request_oid,
            _ID_TCG_ATTEST_QUOTE,
        )

    # 2. TPM key-attestation (v5 credential-activation) profile. request_type =
    #    TPM_KEY_ATTEST_OID (the syntax OID the client sends at GenM, carrying a
    #    KeyAttestChall reqInfo); statement = KeyAttestEvidence. request_type
    #    and statement DIFFER, so key_attest_profile registers under both. Its
    #    build_challenge hook runs a verifier MakeCredential round-trip at GenM
    #    and returns the KeyAttestResp respInfo — there is no PCR negotiation.
    certify_request_oid = os.environ.get(TPM_KEY_ATTEST_REQUEST_OID_ENV, TPM_KEY_ATTEST_REQUEST_OID_DEFAULT)
    certify_url = resolve_url(_ID_KEY_ATTEST_EVIDENCE, certify_request_oid)
    if certify_url:
        profiles.register(
            key_attest_profile(
                request_type_oid=certify_request_oid,
                statement_oid=_ID_KEY_ATTEST_EVIDENCE,
                verifier_url=certify_url,
                ear_oid=ear_oid,
            )
        )
    else:
        logger.warning(
            "build_profile_registry_from_env: no verifier URL for the key-attestation profile "
            "(request_type=%s, statement=%s); skipping it",
            certify_request_oid,
            _ID_KEY_ATTEST_EVIDENCE,
        )

    # 3. jwt_profile for any extra OID configured but not built in (sw / EAR
    #    shapes). A new opaque-evidence type is therefore pure configuration.
    for oid, url in oid_routes.items():
        if profiles.by_request_type(oid) or profiles.by_statement(oid):
            continue
        profiles.register(jwt_profile(request_type_oid=oid, statement_oid=oid, verifier_url=url, ear_oid=ear_oid))

    logger.info("ProfileRegistry initialised from environment: %s", profiles.snapshot())
    return profiles


__all__ = [
    "TPM_KEY_ATTEST_REQUEST_OID_DEFAULT",
    "TPM_KEY_ATTEST_REQUEST_OID_ENV",
    "build_profile_registry_from_env",
]
