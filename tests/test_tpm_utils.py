# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""``tpm_utils`` templates must satisfy the pytss-free attribute floors (anti-drift).

``tpm_utils`` builds templates with the native ``tpm2_pytss.TPMA_OBJECT`` flags;
the floors in :mod:`libattest.formats.tpm.attributes` read the same bits from the
marshalled bytes with **no** ``tpm2-pytss``.  These tests are the contract that the
two representations agree: if a template's attribute word ever drifts from the
floor its role must meet, one of these fails.  This is what lets ``tpm_utils`` be
the single home for templates without re-spelling the floor bit values.

Needs the real native binding (``TPMT_PUBLIC.parse``); collected-but-skipped when
only the ``conftest`` stub is present.
"""

from __future__ import annotations

import pytest

from libattest.formats.tpm.attributes import (
    enforce_iak_floor,
    enforce_ldevid_floor,
    read_object_attributes,
    strip_tpm2b_prefix,
)

# Real binding required to build templates; skip cleanly under the conftest stub.
tpm2_pytss = pytest.importorskip("tpm2_pytss")
if getattr(tpm2_pytss, "__libattest_stub__", False):
    pytest.skip(
        "tpm2_pytss is stubbed; native TPMT_PUBLIC.parse unavailable",
        allow_module_level=True,
    )

from libattest.formats.tpm import tpm_utils  # noqa: E402


def _bare(tpm2b_public) -> bytes:
    """Marshalled ``TPM2B_PUBLIC`` -> bare ``TPMT_PUBLIC``, via the verifier's own strip."""
    return strip_tpm2b_prefix(tpm2b_public.marshal())


@pytest.mark.parametrize("builder", ["ak_template", "iak_template"])
def test_ak_and_iak_templates_pass_the_iak_floor(builder: str) -> None:
    """GIVEN an AK/IAK template WHEN checked THEN it meets the IAK floor (restricted=1, sign=1)."""
    attrs = enforce_iak_floor(_bare(getattr(tpm_utils, builder)()))
    assert attrs.restricted and attrs.sign and not attrs.decrypt
    assert attrs.fixed_tpm and attrs.fixed_parent


def test_devid_template_passes_the_ldevid_floor() -> None:
    """GIVEN a DevID template WHEN checked THEN it meets the LDevID floor (restricted=0, sign=1)."""
    attrs = enforce_ldevid_floor(_bare(tpm_utils.devid_template()))
    assert attrs.sign and not attrs.restricted and not attrs.decrypt
    assert attrs.fixed_tpm and attrs.fixed_parent


def test_devid_template_is_rejected_by_the_iak_floor() -> None:
    """GIVEN an unrestricted DevID WHEN checked against the IAK floor THEN it is rejected."""
    with pytest.raises(ValueError, match="IAK objectAttributes floor"):
        enforce_iak_floor(_bare(tpm_utils.devid_template()))


def test_ek_and_srk_templates_are_restricted_decryption_keys() -> None:
    """GIVEN EK/SRK templates THEN they are restricted *decrypt* (not signing) keys."""
    for builder in (tpm_utils.ek_template, tpm_utils.srk_template):
        attrs = read_object_attributes(_bare(builder()))
        assert attrs.restricted and attrs.decrypt and not attrs.sign
        assert attrs.fixed_tpm and attrs.fixed_parent


def test_default_attr_words_are_exactly_the_expected_bits() -> None:
    """GIVEN the exported default attribute words THEN each equals its exact TPMA_OBJECT bits.

    Pinned as literals so any change to a ``DEFAULT_*_ATTRS`` composition trips this.
    (The floor tests above prove the *security-relevant* bits by cross-checking the
    native flags against the independent pyasn1 parser; this is the exact-value guard.)
    """
    assert int(tpm_utils.DEFAULT_EK_ATTRS) == 0x000300B2  # origin|adminPolicy|restricted|decrypt
    assert int(tpm_utils.DEFAULT_SRK_ATTRS) == 0x00030072  # origin|userWithAuth|restricted|decrypt
    assert int(tpm_utils.DEFAULT_AK_ATTRS) == 0x00050072  # origin|userWithAuth|restricted|sign
    assert int(tpm_utils.DEFAULT_DEVID_ATTRS) == 0x00040072  # origin|userWithAuth|sign (NOT restricted)


def test_ek_template_rejects_non_sha256_hash() -> None:
    """GIVEN a non-SHA-256 hash WHEN ek_template is built THEN it is rejected.

    The stamped authPolicy is the SHA-256 EK Credential Profile policy, so pairing
    it with another nameAlg would be a silent foot-gun.
    """
    with pytest.raises(ValueError, match="SHA-256 EK authPolicy"):
        tpm_utils.ek_template("ecc", "sha384")


def test_ek_template_carries_the_tcg_ek_auth_policy() -> None:
    """GIVEN the default EK template THEN it carries the well-known TCG EK authPolicy."""
    ek = tpm_utils.ek_template()
    assert bytes(ek.publicArea.authPolicy) == tpm_utils.EK_AUTH_POLICY_SHA256


def test_ak_template_is_lazily_exported_from_the_package() -> None:
    """GIVEN the package facade THEN ak_template resolves via the PEP 562 lazy boundary."""
    from libattest.formats import tpm as tpm_pkg

    assert tpm_pkg.ak_template is tpm_utils.ak_template
