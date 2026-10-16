# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""``tpm_client`` must source its AK template from ``tpm_utils`` (single source).

The attester's AK-provisioning template and ``tpm_utils.ak_template`` used to be
two independent copies of the same restricted-signing ``TPMT_PUBLIC``.  These
tests pin the de-duplication: the attester now *is* the shared builder, and the
marshalled template is byte-for-byte unchanged across every family/hash it
supports (so the refactor cannot alter what the TPM actually creates).

Needs the real native binding (``tpm_client`` imports ``tpm2-pytss`` eagerly);
collected-but-skipped when only the ``conftest`` stub is present.
"""

from __future__ import annotations

import pytest

tpm2_pytss = pytest.importorskip("tpm2_pytss")
if getattr(tpm2_pytss, "__libattest_stub__", False):
    pytest.skip(
        "tpm2_pytss is stubbed; native TPMT_PUBLIC.parse unavailable",
        allow_module_level=True,
    )

from libattest.attester import tpm_client  # noqa: E402
from libattest.formats.tpm import tpm_utils  # noqa: E402


def test_ak_template_is_the_shared_tpm_utils_builder() -> None:
    """GIVEN the attester WHEN it needs an AK template THEN it uses the one in tpm_utils."""
    assert tpm_client._ak_template is tpm_utils.ak_template


# Golden marshalled AK templates captured from the PRE-dedup builder (proven
# byte-identical to it at the dedup step).  Pinning the exact bytes — not comparing
# the builder to itself — makes this a real drift guard: a silent change to
# DEFAULT_AK_ATTRS (the ``00050072`` attribute word) or the tpm2-tools spec string
# would trip it.
_AK_TEMPLATE_GOLDEN = {
    ("ecc", "sha1"): "0018002300040005007200000010001800040003001000000000",
    ("ecc", "sha256"): "00180023000b00050072000000100018000b0003001000000000",
    ("ecc", "sha384"): "00180023000c00050072000000100018000c0003001000000000",
    ("ecc", "sha512"): "00180023000d00050072000000100018000d0003001000000000",
    ("rsa", "sha1"): "0018000100040005007200000010001400040800000000000000",
    ("rsa", "sha256"): "00180001000b00050072000000100014000b0800000000000000",
    ("rsa", "sha384"): "00180001000c00050072000000100014000c0800000000000000",
    ("rsa", "sha512"): "00180001000d00050072000000100014000d0800000000000000",
}


@pytest.mark.parametrize(("alg_family", "hash_alg"), list(_AK_TEMPLATE_GOLDEN))
def test_ak_template_matches_golden_bytes(alg_family: str, hash_alg: str) -> None:
    """GIVEN a family/hash THEN the marshalled AK template equals its pinned golden.

    Proves the dedup did not alter what the TPM is asked to create, and that the
    attester (which shares the builder) inherits exactly those bytes.
    """
    golden = _AK_TEMPLATE_GOLDEN[(alg_family, hash_alg)]
    assert tpm_utils.ak_template(alg_family, hash_alg).marshal().hex() == golden
    assert tpm_client._ak_template(alg_family, hash_alg).marshal().hex() == golden
