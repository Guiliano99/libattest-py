# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""HPKE-0 conformance test against draft-ietf-jose-hpke-encrypt-20 Appendix A.1.

Exercises libattest.formats.eat_ear.cwt_jwt_utils (``open_integrated`` / ``seal_integrated``) so the
demo's HPKE-0 core is conformance-pinned to the spec, now on the ``cryptography`` backend.
HPKE-0 = DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM, Integrated Encryption.

Checks:
  * ``test_open_published_vector`` — open the draft's *published* compact JWE (AEAD
    integrity fails unless key/enc/ct/aad/info all match the spec).  This is the anchor
    proving cryptography's HPKE is byte-compatible with JOSE-HPKE-0.
  * ``test_roundtrip`` — seal->open with the draft's recipient key + a tamper negative.
  * ``test_aad_helpers_present`` — guard: the private aad-capable HPKE helpers exist.

NOTE: ``PUBLISHED_COMPACT_JWE`` is transcribed from draft-20 App. A.1 (Figure 3); long
base64 is error-prone — if ``test_open_published_vector`` fails, re-verify those bytes
against the draft before assuming a bug.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from libattest.formats.eat_ear import cwt_jwt_utils

# draft-ietf-jose-hpke-encrypt-20, Appendix A.1 (HPKE-0) recipient key (incl. private d).
RECIPIENT_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0",
    "y": "ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI",
    "d": "aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4",
    "alg": "HPKE-0",
    "use": "enc",
    "kid": "KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM",
}

# Compact JWE (App. A.1, Figure 3): protected '.' enc '.' iv '.' ciphertext '.' tag
# (Integrated => empty IV and Tag).  Transcribed from draft-20 — VERIFY byte-exact.
PUBLISHED_COMPACT_JWE = (
    "eyJhbGciOiJIUEtFLTAiLCJraWQiOiJLZnZELWVZYXluVUtiYTBvdy12OXVvRVYtdHdWNm1ZRHlpQU9XTzZMb1BNIn0"
    "."
    "BKqUaiyoPbH1jnjApcpjGqswg7npGSSXFcFv1nGaL6YYs3S27c8Yi5V5rsds91bV_UjdqzLlj2zuuAPWetLMab8"
    "."
    ""
    "."
    "fO8VQt1DsdgtijGci90sO8sNvws6im8Yko4NnMWXVAM5GaHbHYRSGnjs6M7GnkcaTrEjy8cxDDLZFKTwMdYGOjYBsbTVVAoIImVd8tXZNjQswaPU8t8OP1jCwo6iw8t4-Hm6hCE61uzhEd_r9XkN4blHjrcAoCICcwqn_5lgJCTPQezJtiTAhrtHpC1quPA3aO2Pyhui5CzOtk967IC8v28jq6K7C3mbu-m10bo0aWqdybibCiiS5A89PXFWurW83HNnJFdoiqZRTtF4d_OAQ2Jq9FCrahrh43Xqp1z3HYjf73_rOHYWXzv8jGorDAKjsPgxYN_9TgGUstjiRIMLj9dJXxqrPkRLQ4VSAzVWCNe5MabAR1sFFB5tx_gA"
    "."
    ""
)


def test_open_published_vector() -> None:
    header, plaintext = cwt_jwt_utils.open_integrated(PUBLISHED_COMPACT_JWE, RECIPIENT_JWK)
    assert header["alg"] == "HPKE-0"
    assert plaintext, "recovered plaintext must be non-empty"


def test_roundtrip() -> None:
    pub = {k: v for k, v in RECIPIENT_JWK.items() if k != "d"}
    plaintext = b"eyJhbGciOiJFUzI1NiJ9.<inner-EAT-JWS>.<sig>"  # stand-in EAT-JWS

    jwe = cwt_jwt_utils.seal_integrated(plaintext, {"kid": RECIPIENT_JWK["kid"]}, pub)
    header, recovered = cwt_jwt_utils.open_integrated(jwe, RECIPIENT_JWK)
    assert header["alg"] == "HPKE-0"
    assert recovered == plaintext


def test_tampered_ciphertext_rejected() -> None:
    pub = {k: v for k, v in RECIPIENT_JWK.items() if k != "d"}
    jwe = cwt_jwt_utils.seal_integrated(b"secret", {}, pub)
    parts = jwe.split(".")
    parts[3] = ("B" if parts[3][0] != "B" else "C") + parts[3][1:]
    with pytest.raises(InvalidTag):
        cwt_jwt_utils.open_integrated(".".join(parts), RECIPIENT_JWK)


def test_non_empty_iv_or_tag_rejected() -> None:
    pub = {k: v for k, v in RECIPIENT_JWK.items() if k != "d"}
    p, enc, _iv, ct, _tag = cwt_jwt_utils.seal_integrated(b"x", {}, pub).split(".")
    with pytest.raises(ValueError, match="empty IV and Tag"):
        cwt_jwt_utils.open_integrated(".".join([p, enc, cwt_jwt_utils.b64u_encode(b"iv"), ct, ""]), RECIPIENT_JWK)


def test_aad_helpers_present() -> None:
    # Guard: the JOSE-HPKE-0 aad binding depends on cryptography's private single-shot
    # helpers; if a release relocates them, importing jose_hpke raises, so reaching here
    # means they bound successfully.
    assert callable(cwt_jwt_utils._encrypt_with_aad)
    assert callable(cwt_jwt_utils._decrypt_with_aad)
