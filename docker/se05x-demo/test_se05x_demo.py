# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Live tests of the SE05x attestation demo against the simulator.

``make se05x-test`` runs them in the compose ``test`` service, after the one-shot
``provision`` service has certified the simulator's attestation key and written the
demo root to ``$TRUST_DIR/root.pem``. When no simulator answers at
``$SE05X_HOST:$SE05X_PORT``, every test fails if ``SE05X_HOST`` is set (compose sets
it) and skips otherwise.

A key imported by the host is not tested live: :class:`Se05xClient` cannot write a
key pair with its private part. ``tests/test_se05x_verifier.py`` (``origin-imported``)
covers that origin gate offline.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

# This folder is not a package; put it on the path so the demo module imports.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import se05x_demo  # noqa: E402

from libattest.attester.se05x_client import Se05xClient  # noqa: E402
from libattest.formats.eat_ear import cwt_jwt_utils  # noqa: E402
from libattest.formats.se05x import apdu  # noqa: E402
from libattest.verifier.trust import validate_ek_chain  # noqa: E402

HOST = os.environ.get("SE05X_HOST", "127.0.0.1")
PORT = int(os.environ.get("SE05X_PORT", "8050"))
TRUST_DIR = Path(os.environ.get("TRUST_DIR", "trust"))


def _client() -> Se05xClient:
    """Return a connected client with the applet selected.

    An unreachable SE fails the test when ``SE05X_HOST`` names it, and skips it otherwise.
    """
    try:
        client = Se05xClient(HOST, PORT)
    except OSError as exc:
        message = f"no SE05x simulator at {HOST}:{PORT}: {exc}"
        if "SE05X_HOST" in os.environ:
            pytest.fail(message)
        pytest.skip(message)
    client.select()
    return client


def _root() -> x509.Certificate:
    return x509.load_pem_x509_certificate((TRUST_DIR / "root.pem").read_bytes())


def test_the_demo_accepts_fresh_evidence_and_refuses_the_replay(capsys: pytest.CaptureFixture[str]) -> None:
    """GIVEN a provisioned simulator WHEN the demo runs THEN it succeeds end to end."""
    _client().close()

    assert se05x_demo.run_demo(HOST, PORT, TRUST_DIR)
    assert "OK: fresh Evidence accepted, replay refused" in capsys.readouterr().out


def test_the_ear_carries_exactly_the_planned_claims() -> None:
    """GIVEN fresh Evidence for an SE-generated key THEN the EAR echoes the nonce and has the exact submods."""
    with _client() as se:
        engine, verifier = se05x_demo.make_engine(_root())
        tx_id = os.urandom(16)
        nonce = se05x_demo.issue_nonce(engine, tx_id)
        bundle, spki = se05x_demo.attest(se, nonce)

    outcome = engine.verify_bundle(bundle, tx_id, pubkey=spki)

    assert outcome.accepted, se05x_demo.verdict(outcome)
    assert outcome.first_ear is not None
    claims = cwt_jwt_utils.verify_es256(outcome.first_ear, verifier.ear_verification_pem())
    assert cwt_jwt_utils.b64u_decode(claims["eat_nonce"]) == nonce
    assert claims["submods"] == {
        "SE05X": {
            "ear.status": "affirming",
            "ear.trustworthiness-vector": {"instance-identity": 2},
            "ear.appraisal-policy-id": "policy:SE05X/demo-sim-root",
        }
    }


def test_a_nonce_from_another_transaction_is_refused() -> None:
    """GIVEN Evidence under the nonce of transaction A WHEN submitted under transaction B THEN it is refused."""
    with _client() as se:
        engine, _ = se05x_demo.make_engine(_root())
        tx_a, tx_b = os.urandom(16), os.urandom(16)
        nonce_a = se05x_demo.issue_nonce(engine, tx_a)
        se05x_demo.issue_nonce(engine, tx_b)
        bundle, spki = se05x_demo.attest(se, nonce_a)

    outcome = engine.verify_bundle(bundle, tx_b, pubkey=spki)

    assert not outcome.accepted
    assert "does not match the RA nonce" in se05x_demo.verdict(outcome)


def test_the_attestation_certificate_chains_to_the_provisioned_root() -> None:
    """GIVEN the provisioned SE THEN 0xF0000013 certifies 0xF0000012, names the chip id and chains to root.pem."""
    with _client() as se:
        leaf = x509.load_der_x509_certificate(se.read_object(apdu.CERT_OBJECT_ID))
        point = se.read_object(apdu.ATTEST_KEY_ID)
        chip_id = se.read_object(apdu.UNIQUE_ID_OBJECT_ID)
    root = _root()

    validate_ek_chain(chain=[leaf], roots=[root])
    assert root.subject.rfc4514_string() == "CN=libattest demo SE05x attestation root (not NXP)"
    leaf_point = leaf.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert leaf_point == point
    assert leaf.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == chip_id.hex().upper()
