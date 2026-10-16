# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM 2.0 key templates and default object-attribute sets — one source of truth.

Every TPM key this project creates — EK, SRK (the storage "SK"), AK/IAK, and
DevID — gets its ``TPMT_PUBLIC`` template and its default ``TPMA_OBJECT``
attribute word from **here**, instead of being re-spelled in the attester, the
demos, and the fixtures (as it was in ``tpm_client._ak_template`` and the
now-retired root scratch scripts).

Two representations meet at this seam by design:

* the templates are built with the native ``tpm2_pytss.TPMA_OBJECT`` flags (the
  library's own canonical bit constants — not literals re-typed here); while
* the *floors* those templates must satisfy live in the pytss-free
  :mod:`libattest.formats.tpm.attributes` (``enforce_iak_floor`` /
  ``enforce_ldevid_floor``), which read the same bits from marshalled bytes so
  the MockCA (no native binding) can enforce them too.

``tests/test_tpm_utils.py`` asserts the two agree — every template this module
emits passes its role's floor — so the pytss and pyasn1 sides can never drift.

Native-binding boundary: this module constructs real ``TPMT_PUBLIC`` values and
therefore needs ``tpm2-pytss``.  It stays behind the PEP 562 lazy boundary in
:mod:`libattest.formats.tpm` (registered in ``_LAZY_MODULE_EXPORTS``), so
importing the package without the ``[tpm]`` extra never pulls the native library.

Attribute floors (source: TCG "TPM 2.0 Keys for Device Identity and Attestation"):

===========  ==========  ========  =======  =========  ===========
role         restricted  sign      decrypt  fixedTPM   fixedParent
===========  ==========  ========  =======  =========  ===========
EK           1           0         1        1          1           (§ EK profile)
SRK ("SK")   1           0         1        1          1
AK / IAK     1           1         0        1          1           ([DEV-ID] §4.1)
DevID        0           1         0        1          1           ([DEV-ID] §4.2)
===========  ==========  ========  =======  =========  ===========
"""

from __future__ import annotations

from libattest._pytss import require_pytss

require_pytss()

from tpm2_pytss import (  # noqa: E402
    TPM2_ALG,
    TPM2B_PUBLIC,
    TPMA_OBJECT,
    TPMT_PUBLIC,
)

#: Friendly hash name -> TPM algorithm id (TCG Algorithm Registry).  The single
#: map, reused by every builder here AND by the attester (``tpm_client`` imports
#: it), for both the signing scheme and the name algorithm.
HASH_ALG_IDS = {
    "sha1": TPM2_ALG.SHA1,
    "sha256": TPM2_ALG.SHA256,
    "sha384": TPM2_ALG.SHA384,
    "sha512": TPM2_ALG.SHA512,
}

#: TCG EK Credential Profile ``authPolicy`` for a SHA-256 EK: the digest of
#: ``TPM2_PolicySecret(TPM_RH_ENDORSEMENT)``.  The well-known value every standard
#: EK carries; an ``ActivateCredential`` EK policy session must satisfy it.  Kept
#: here as the single home (it was duplicated verbatim in the demo scripts).
EK_AUTH_POLICY_SHA256 = bytes.fromhex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")

# Shared floor bits every key below carries: TPM-bound, non-reparentable, and
# TPM-originated sensitive area.
_FIXED_ORIGIN = TPMA_OBJECT.FIXEDTPM | TPMA_OBJECT.FIXEDPARENT | TPMA_OBJECT.SENSITIVEDATAORIGIN

#: EK: restricted decryption key, policy-authorized (TCG EK Credential Profile).
DEFAULT_EK_ATTRS = _FIXED_ORIGIN | TPMA_OBJECT.ADMINWITHPOLICY | TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.DECRYPT

#: SRK / storage "SK": restricted decryption parent, auth-value authorized.
DEFAULT_SRK_ATTRS = _FIXED_ORIGIN | TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.DECRYPT

#: AK / IAK: restricted signing key ([DEV-ID] §4.1: restricted=1, sign=1).
DEFAULT_AK_ATTRS = _FIXED_ORIGIN | TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.RESTRICTED | TPMA_OBJECT.SIGN_ENCRYPT

#: DevID: UNrestricted signing key ([DEV-ID] §4.2: restricted=0, sign=1).
DEFAULT_DEVID_ATTRS = _FIXED_ORIGIN | TPMA_OBJECT.USERWITHAUTH | TPMA_OBJECT.SIGN_ENCRYPT


def _name_alg(hash_alg: str):
    """Resolve a friendly hash name to its TPM algorithm id, or raise ``ValueError``."""
    try:
        return HASH_ALG_IDS[hash_alg]
    except KeyError:
        raise ValueError(f"unsupported hash {hash_alg!r}; pick one of {list(HASH_ALG_IDS)}") from None


def _signing_spec(alg_family: str, hash_alg: str) -> str:
    """tpm2-tools ``type:scheme:symmetric`` spec for a sign-only key.

    The trailing ``:null`` symmetric is mandatory for a restricted signing key —
    otherwise tpm2-pytss defaults it to AES, which the TPM rejects for a signer.
    """
    if alg_family == "rsa":
        return f"rsa2048:rsassa-{hash_alg}:null"
    if alg_family == "ecc":
        return f"ecc256:ecdsa-{hash_alg}:null"
    raise ValueError("alg_family must be 'rsa' or 'ecc'")


def _decryption_spec(alg_family: str) -> str:
    """tpm2-tools spec for a restricted decryption key (``null`` scheme, AES sym)."""
    if alg_family == "rsa":
        return "rsa2048:null:aes128cfb"
    if alg_family == "ecc":
        return "ecc256:null:aes128cfb"
    raise ValueError("alg_family must be 'rsa' or 'ecc'")


def _template(spec: str, attrs: TPMA_OBJECT, hash_alg: str) -> TPM2B_PUBLIC:
    """Parse a tpm2-tools *spec* into a ``TPM2B_PUBLIC`` with *attrs* and name alg."""
    public_area = TPMT_PUBLIC.parse(alg=spec, objectAttributes=attrs, nameAlg=_name_alg(hash_alg))
    return TPM2B_PUBLIC(publicArea=public_area)


def ak_template(alg_family: str = "ecc", hash_alg: str = "sha256") -> TPM2B_PUBLIC:
    """Restricted *signing* key template — an Attestation Key / IAK ([DEV-ID] §4.1).

    ``restricted=1`` is what makes the TPM enforce the ``TPM_GENERATED_VALUE``
    rule, so the key can only sign TPM-produced digests, never attacker-chosen
    bytes shaped like an attestation.  The signing scheme (and thus the hash used
    by ``TPM2_Quote``) is fixed here at creation time.
    """
    return _template(_signing_spec(alg_family, hash_alg), DEFAULT_AK_ATTRS, hash_alg)


#: An IAK is an *Initial* AK — the same restricted-signing template as any AK.
iak_template = ak_template


def devid_template(alg_family: str = "ecc", hash_alg: str = "sha256") -> TPM2B_PUBLIC:
    """UNrestricted *signing* key template — an (I/L)DevID ([DEV-ID] §4.2, restricted=0)."""
    return _template(_signing_spec(alg_family, hash_alg), DEFAULT_DEVID_ATTRS, hash_alg)


def srk_template(alg_family: str = "ecc", hash_alg: str = "sha256") -> TPM2B_PUBLIC:
    """Storage Root Key ("SK") template — restricted decryption parent for ordinary keys."""
    return _template(_decryption_spec(alg_family), DEFAULT_SRK_ATTRS, hash_alg)


def ek_template(alg_family: str = "ecc", hash_alg: str = "sha256") -> TPM2B_PUBLIC:
    """Endorsement Key template — restricted decryption key with the TCG EK authPolicy.

    A pure, TPM-less *default* EK template for the offline demos and fixtures.
    The authoritative, NV-certificate-bound EK is provisioned by
    :meth:`libattest.attester.tpm_client.TpmClient.provision_ek` via pytss
    ``create_ek_template`` + ``NVReadEK``; this builder needs no live TPM.

    Only ``hash_alg="sha256"`` is offered: the stamped ``authPolicy`` is the
    SHA-256 EK Credential Profile policy, so pairing it with a different
    ``nameAlg`` would yield a template no ``ActivateCredential`` session could
    ever satisfy.  A non-SHA-256 request is rejected, not silently mis-paired.
    """
    if hash_alg != "sha256":
        raise ValueError(f"ek_template only provides the SHA-256 EK authPolicy; got hash_alg={hash_alg!r}")
    tpm2b = _template(_decryption_spec(alg_family), DEFAULT_EK_ATTRS, hash_alg)
    tpm2b.publicArea.authPolicy = EK_AUTH_POLICY_SHA256
    return tpm2b


__all__ = [
    "DEFAULT_AK_ATTRS",
    "DEFAULT_DEVID_ATTRS",
    "DEFAULT_EK_ATTRS",
    "DEFAULT_SRK_ATTRS",
    "EK_AUTH_POLICY_SHA256",
    "HASH_ALG_IDS",
    "ak_template",
    "devid_template",
    "ek_template",
    "iak_template",
    "srk_template",
]
