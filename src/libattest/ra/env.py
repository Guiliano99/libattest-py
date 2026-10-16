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

The environment is read **once**, into :class:`RaEnvConfig`, and every decision after
that is made against that object.  Reading ``os.environ`` at a dozen points inside the
builder meant the deployment's configuration existed only as the sum of those reads:
there was nothing to log, nothing to validate up front, and nothing a test could
construct without monkeypatching the process environment.

Which profile a route gets is likewise a configuration choice rather than a property of
the code.  A route may name a factory (:data:`PROFILE_BUILDERS`) instead of relying on
the OID being one the builder happens to recognise; without a name the two built-in TPM
OIDs keep their special handling and everything else becomes a ``jwt_profile``, exactly
as before.

Env vars consumed
------------------
``VERIFIER_OID_ROUTES``    JSON map ``{"<oid-dot>": "<url>", ...}`` — evidence-
                           type OID -> verifier URL. A value may also be an
                           object ``{"url": "...", "profile": "<name>"}`` to
                           pick the profile factory explicitly. Empty/unset is
                           allowed if a fallback is set.
``VERIFIER_URL_FALLBACK``  Default URL used when the OID lookup does not
                           resolve.
``TPM_QUOTE_PCRS``         PCR set the quote profile broadcasts in respInfo
                           (comma-separated ints; default ``"0,1,2,3,4"``).
``TPM_PCR_SELECTION_OID``  Quote-leg request-type OID (also read by
                           ``libattest.formats.tpm.structures`` at import
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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from libattest import get_nonce_request_oid_for_name, get_oid_by_name
from libattest.ra.profile import AttestationProfile, jwt_profile, key_attest_profile, tpm_profile
from libattest.ra.registry import ProfileRegistry

logger = logging.getLogger(__name__)

_ID_TCG_ATTEST_QUOTE = get_oid_by_name("tcg-attest-quote")
_ID_KEY_ATTEST_EVIDENCE = get_oid_by_name("key-attest")

# The platform demo advertises ak-1 as its first quote certificate-name label.
# The RA/CA selects and returns that label in TPM20QuoteRespInfo.
_TPM_QUOTE_SELECTED_CERTIFICATE_NAME = "ak-1"

_DEFAULT_QUOTE_PCRS = [0, 1, 2, 3, 4]


@dataclass(frozen=True)
class RouteConfig:
    """One configured verifier route: where it is, and which profile handles it.

    Attributes
    ----------
    url:
        Base URL of the verifier serving this evidence type.
    profile:
        Name of the :data:`PROFILE_BUILDERS` entry to build this route with, or
        ``None`` to let the OID decide (the two built-in TPM OIDs get their own
        profiles; anything else becomes a ``jwt_profile``).

    """

    url: str
    profile: str | None = None


@dataclass(frozen=True)
class RaEnvConfig:
    """A deployment's RA wiring, read from the environment exactly once.

    Attributes
    ----------
    oid_routes:
        Evidence-type OID -> :class:`RouteConfig`.
    fallback_url:
        Verifier URL used for any profile whose OID is not in *oid_routes*.
    quote_pcrs:
        PCR set the TPM quote profile broadcasts in its respInfo.
    ear_oid:
        The X.509 extension OID issued EARs are embedded under.
    quote_certificate_name:
        The AK certificate-name label the RA selects in ``TPM20QuoteRespInfo``.

    """

    oid_routes: Mapping[str, RouteConfig] = field(default_factory=dict)
    fallback_url: str | None = None
    quote_pcrs: list[int] = field(default_factory=lambda: list(_DEFAULT_QUOTE_PCRS))
    ear_oid: str | None = None
    quote_certificate_name: str = _TPM_QUOTE_SELECTED_CERTIFICATE_NAME

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> RaEnvConfig:
        """Read the RA env vars into one config object.

        *environ* defaults to :data:`os.environ`; passing a plain mapping is how a test
        (or a second deployment in the same process) configures the RA without touching
        the process environment.

        :raises RuntimeError: ``VERIFIER_OID_ROUTES`` is present but not a JSON object.
        """
        env = os.environ if environ is None else environ
        return cls(
            oid_routes=_parse_oid_routes(env.get("VERIFIER_OID_ROUTES", "")),
            fallback_url=(env.get("VERIFIER_URL_FALLBACK") or "").strip().rstrip("/") or None,
            quote_pcrs=_parse_pcr_list(env.get("TPM_QUOTE_PCRS", "0,1,2,3,4")),
            ear_oid=get_oid_by_name("ear-extension"),
        )

    def resolve_url(self, *oids: str | None) -> str | None:
        """Return the first configured URL among *oids*, else the fallback."""
        for oid in oids:
            route = self.oid_routes.get(oid) if oid else None
            if route is not None:
                return route.url
        return self.fallback_url

    def profile_name(self, *oids: str | None) -> str | None:
        """Return the explicitly configured profile name among *oids*, if any."""
        for oid in oids:
            route = self.oid_routes.get(oid) if oid else None
            if route is not None and route.profile:
                return route.profile
        return None


def _quote_builder(oid: str, url: str, config: RaEnvConfig) -> AttestationProfile:
    """Build the TPM 2.0 platform (quote) profile for *oid*."""
    return tpm_profile(
        request_type_oid=get_nonce_request_oid_for_name("tpm-quote-request"),
        statement_oid=oid,
        verifier_url=url,
        pcrs=config.quote_pcrs,
        certificate_name=config.quote_certificate_name,
        ear_oid=config.ear_oid,
    )


def _key_attest_builder(oid: str, url: str, config: RaEnvConfig) -> AttestationProfile:
    """Build the TPM key-attestation (v5 credential-activation) profile for *oid*."""
    return key_attest_profile(
        request_type_oid=get_nonce_request_oid_for_name("key-attest-request"),
        statement_oid=oid,
        verifier_url=url,
        ear_oid=config.ear_oid,
    )


def _jwt_builder(oid: str, url: str, config: RaEnvConfig) -> AttestationProfile:
    """Build a plain opaque-evidence profile for *oid* (request and statement alike)."""
    return jwt_profile(request_type_oid=oid, statement_oid=oid, verifier_url=url, ear_oid=config.ear_oid)


#: Profile factories a route may name in ``VERIFIER_OID_ROUTES``.  Adding an evidence
#: type to a deployment is then configuration rather than an edit to this module.
PROFILE_BUILDERS: dict[str, Callable[[str, str, RaEnvConfig], AttestationProfile]] = {
    "tpm-quote": _quote_builder,
    "key-attest": _key_attest_builder,
    "jwt": _jwt_builder,
}

#: OIDs whose profile is implied when a route does not name one, preserving the
#: original builder's behaviour for deployments that predate ``profile``.
_BUILTIN_PROFILE_BY_STATEMENT: dict[str, str] = {
    _ID_TCG_ATTEST_QUOTE: "tpm-quote",
    _ID_KEY_ATTEST_EVIDENCE: "key-attest",
}


def _parse_oid_routes(raw: str) -> dict[str, RouteConfig]:
    """Decode the ``VERIFIER_OID_ROUTES`` JSON env var, with a clear error."""
    raw = raw.strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"VERIFIER_OID_ROUTES is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("VERIFIER_OID_ROUTES must decode to a JSON object")

    routes: dict[str, RouteConfig] = {}
    for oid, value in data.items():
        if isinstance(value, Mapping):
            url = str(value.get("url", "")).rstrip("/")
            profile = value.get("profile")
            if not url:
                raise RuntimeError(f"VERIFIER_OID_ROUTES entry {oid!r} has no 'url'")
            if profile is not None and str(profile) not in PROFILE_BUILDERS:
                raise RuntimeError(
                    f"VERIFIER_OID_ROUTES entry {oid!r} names unknown profile {profile!r}; "
                    f"known profiles: {sorted(PROFILE_BUILDERS)}"
                )
            routes[str(oid)] = RouteConfig(url=url, profile=None if profile is None else str(profile))
        else:
            routes[str(oid)] = RouteConfig(url=str(value).rstrip("/"))
    return routes


def _parse_pcr_list(value: str) -> list[int]:
    """Parse ``TPM_QUOTE_PCRS`` (e.g. ``"0,1,2,3,4"``) into a list of ints.

    Empty / invalid entries are dropped with a warning; an empty or unparseable
    value falls back to ``[0, 1, 2, 3, 4]`` so a typo never breaks startup.
    """
    if not value:
        return list(_DEFAULT_QUOTE_PCRS)
    out: list[int] = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            index = int(token)
        except ValueError:
            logger.warning("TPM_QUOTE_PCRS: ignoring non-integer entry %r", token)
            continue
        if index < 0:
            logger.warning("TPM_QUOTE_PCRS: ignoring negative PCR index %d", index)
            continue
        out.append(index)
    return out or list(_DEFAULT_QUOTE_PCRS)


def build_profile_registry(config: RaEnvConfig) -> ProfileRegistry:
    """Build a :class:`ProfileRegistry` from an explicit :class:`RaEnvConfig`.

    Seeds, in order:

    1. the **TPM platform (quote) profile** and the **TPM key-attestation (v5)
       profile**, whose OIDs the builder recognises without being told;
    2. every remaining configured OID, through the factory its route names, or
       ``jwt_profile`` when it names none — so a new opaque-evidence type is pure
       configuration.

    Raises
    ------
    RuntimeError
        Neither routes nor a fallback URL is configured — nothing could ever
        resolve a verifier URL.

    """
    if not (config.oid_routes or config.fallback_url):
        raise RuntimeError(
            "build_profile_registry: refusing to start — no routing configured. "
            "Set at least one of VERIFIER_OID_ROUTES or VERIFIER_URL_FALLBACK."
        )

    profiles = ProfileRegistry()

    # 1. The two built-in TPM profiles. Each is keyed by its statement OID but may be
    #    routed by either its statement or its request-type OID, so both are offered to
    #    resolve_url before falling back.
    for statement_oid, request_name in (
        (_ID_TCG_ATTEST_QUOTE, "tpm-quote-request"),
        (_ID_KEY_ATTEST_EVIDENCE, "key-attest-request"),
    ):
        request_oid = get_nonce_request_oid_for_name(request_name)
        url = config.resolve_url(statement_oid, request_oid)
        if not url:
            logger.warning(
                "build_profile_registry: no verifier URL for the %s profile "
                "(request_type=%s, statement=%s); skipping it",
                _BUILTIN_PROFILE_BY_STATEMENT[statement_oid],
                request_oid,
                statement_oid,
            )
            continue
        name = config.profile_name(statement_oid, request_oid) or _BUILTIN_PROFILE_BY_STATEMENT[statement_oid]
        profiles.register(PROFILE_BUILDERS[name](statement_oid, url, config))

    # 2. Everything else that was configured but is not built in. A route that names a
    #    profile gets it; one that does not is opaque evidence.
    for oid, route in config.oid_routes.items():
        if profiles.by_request_type(oid) or profiles.by_statement(oid):
            continue
        profiles.register(PROFILE_BUILDERS[route.profile or "jwt"](oid, route.url, config))

    logger.info("ProfileRegistry initialised from environment: %s", profiles.snapshot())
    return profiles


def build_profile_registry_from_env() -> ProfileRegistry:
    """Build a :class:`ProfileRegistry` from the canonical RA env vars.

    Thin wrapper over :func:`build_profile_registry` — see :class:`RaEnvConfig` for the
    values it reads.

    Raises
    ------
    RuntimeError
        Neither ``VERIFIER_OID_ROUTES`` nor ``VERIFIER_URL_FALLBACK`` is
        configured.

    """
    return build_profile_registry(RaEnvConfig.from_env())


__all__ = [
    "PROFILE_BUILDERS",
    "RaEnvConfig",
    "RouteConfig",
    "build_profile_registry",
    "build_profile_registry_from_env",
]
