# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for env → :class:`~libattest.ra.ProfileRegistry` wiring.

Moved here from the MockCA's ``test_profile_registry_env.py``: this wiring now
lives in ``libattest.ra.env`` / ``RemoteAttestationEngine.from_env()``.
"""

from __future__ import annotations

import json

import pytest

from libattest import get_oid_by_name
from libattest.formats.tpm import decode_tpm20_quote_resp_info
from libattest.ra import RemoteAttestationEngine
from libattest.ra.env import (
    RaEnvConfig,
    RouteConfig,
    build_profile_registry,
    build_profile_registry_from_env,
)

ID_TCG_ATTEST_QUOTE = get_oid_by_name("tcg-attest-quote")
ID_TCG_ATTEST_CERTIFY = get_oid_by_name("tcg-attest-certify")
ID_KEY_ATTEST_EVIDENCE = get_oid_by_name("key-attest")


def _set_routes(monkeypatch: pytest.MonkeyPatch, routes: dict[str, str], fallback: str | None = None) -> None:
    monkeypatch.setenv("VERIFIER_OID_ROUTES", json.dumps(routes))
    if fallback is not None:
        monkeypatch.setenv("VERIFIER_URL_FALLBACK", fallback)
    else:
        monkeypatch.delenv("VERIFIER_URL_FALLBACK", raising=False)


def test_no_routing_configured_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN neither env var is set WHEN building THEN RuntimeError surfaces the deployment mistake at startup."""
    monkeypatch.delenv("VERIFIER_OID_ROUTES", raising=False)
    monkeypatch.delenv("VERIFIER_URL_FALLBACK", raising=False)

    with pytest.raises(RuntimeError, match="no routing configured"):
        build_profile_registry_from_env()


def test_quote_profile_seeded_from_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN a route for the quote statement OID WHEN built THEN the TPM quote profile is registered."""
    _set_routes(monkeypatch, {ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444"})

    profiles = build_profile_registry_from_env()

    quote = profiles.by_statement(ID_TCG_ATTEST_QUOTE)
    assert quote is not None
    assert quote.statement_oid == ID_TCG_ATTEST_QUOTE
    # Request and response OIDs are distinct wire positions (see quote_profile).
    assert quote.request_type_oid != quote.response_type_oid


def test_quote_profile_returns_selected_ak_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN the TPM quote profile WHEN issuing a nonce THEN it selects ak-1."""
    _set_routes(monkeypatch, {ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444"})

    quote = build_profile_registry_from_env().by_statement(ID_TCG_ATTEST_QUOTE)

    assert quote is not None
    response_info = quote.build_resp_info(0x000B)
    assert response_info is not None
    assert decode_tpm20_quote_resp_info(response_info) == ("ak-1", [0, 1, 2, 3, 4], 0x000B)


def test_key_attest_profile_seeded_from_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN a route for the key-attest statement OID WHEN built THEN the key-attestation profile is registered."""
    _set_routes(monkeypatch, {ID_KEY_ATTEST_EVIDENCE: "http://tpm-verifier:8444"})

    profiles = build_profile_registry_from_env()

    certify = profiles.by_statement(ID_KEY_ATTEST_EVIDENCE)
    assert certify is not None
    assert certify.statement_oid == ID_KEY_ATTEST_EVIDENCE


def test_extra_oid_becomes_jwt_profile_pure_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN an OID with no built-in handler WHEN built THEN it becomes a plain jwt_profile — no code change needed."""
    new_oid = "1.3.6.1.4.1.99999.7"
    _set_routes(
        monkeypatch,
        {ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444", new_oid: "http://sw-verifier:9000"},
    )

    profiles = build_profile_registry_from_env()

    profile = profiles.by_statement(new_oid)
    assert profile is not None
    assert profile.verifier_url == "http://sw-verifier:9000"


def test_fallback_url_used_when_no_oid_route_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN only a fallback URL WHEN built THEN the quote profile resolves through it."""
    _set_routes(monkeypatch, {}, fallback="http://fallback-verifier:9999")

    profiles = build_profile_registry_from_env()

    quote = profiles.by_statement(ID_TCG_ATTEST_QUOTE)
    assert quote is not None
    assert quote.verifier_url == "http://fallback-verifier:9999"


def test_malformed_verifier_oid_routes_json_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERIFIER_OID_ROUTES", "{not json")

    with pytest.raises(RuntimeError, match="not valid JSON"):
        build_profile_registry_from_env()


def test_engine_from_env_wires_a_working_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    """GIVEN valid env vars WHEN RemoteAttestationEngine.from_env() is called THEN it returns a usable engine."""
    _set_routes(monkeypatch, {ID_TCG_ATTEST_QUOTE: "http://tpm-verifier:8444"})

    engine = RemoteAttestationEngine.from_env()

    assert engine.profiles.by_statement(ID_TCG_ATTEST_QUOTE) is not None
    assert engine.nonce_store is not None


# ── the environment as one object, and profiles chosen by name ───────────────────
def test_the_config_can_be_built_without_touching_the_process_environment() -> None:
    """GIVEN a plain mapping THEN the RA is configurable without monkeypatching os.environ."""
    config = RaEnvConfig.from_env(
        {"VERIFIER_OID_ROUTES": json.dumps({ID_TCG_ATTEST_QUOTE: "http://tpm:8444"}), "TPM_QUOTE_PCRS": "0,7"}
    )

    assert config.oid_routes[ID_TCG_ATTEST_QUOTE] == RouteConfig(url="http://tpm:8444")
    assert config.quote_pcrs == [0, 7]
    assert build_profile_registry(config).by_statement(ID_TCG_ATTEST_QUOTE) is not None


def test_a_route_can_name_the_profile_that_handles_it() -> None:
    """GIVEN an explicit profile name THEN that factory builds the route.

    Which profile an OID gets used to be a property of this module's hardcoded OID
    list; a deployment with its own quote OID had no way to say so.
    """
    own_oid = "1.3.6.1.4.1.99999.42"
    config = RaEnvConfig.from_env(
        {"VERIFIER_OID_ROUTES": json.dumps({own_oid: {"url": "http://tpm:8444", "profile": "tpm-quote"}})}
    )

    profile = build_profile_registry(config).by_statement(own_oid)

    assert profile is not None
    assert profile.resp_info_label == "TPM20QuoteRespInfo", "it was built as a quote profile, not an opaque one"
    assert profile.build_resp_info(0x000B) is not None


def test_an_unnamed_route_is_still_opaque_evidence() -> None:
    """GIVEN no profile name THEN the pre-existing jwt_profile default applies."""
    own_oid = "1.3.6.1.4.1.99999.43"
    config = RaEnvConfig.from_env({"VERIFIER_OID_ROUTES": json.dumps({own_oid: "http://sw:9000"})})

    profile = build_profile_registry(config).by_statement(own_oid)

    assert profile is not None
    assert profile.build_resp_info(0x000B) is None


def test_an_unknown_profile_name_is_refused_at_startup() -> None:
    """GIVEN a typo in the profile name THEN fail loudly rather than silently fall back."""
    with pytest.raises(RuntimeError, match="unknown profile"):
        RaEnvConfig.from_env(
            {"VERIFIER_OID_ROUTES": json.dumps({"1.2.3": {"url": "http://v", "profile": "tpm-qoute"}})}
        )


def test_a_route_object_without_a_url_is_refused() -> None:
    """GIVEN a route object missing its url THEN say so instead of routing nowhere."""
    with pytest.raises(RuntimeError, match="has no 'url'"):
        RaEnvConfig.from_env({"VERIFIER_OID_ROUTES": json.dumps({"1.2.3": {"profile": "jwt"}})})
