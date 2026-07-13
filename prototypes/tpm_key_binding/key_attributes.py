# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""The draft-reddy-rats-key-binding ``key-attributes`` claim, sourced from a TPM.

draft-reddy-rats-key-binding-01 §3 defines a ``key-attributes`` map so a Verifier
can tell a Relying Party *how well protected* the attested Subject Key is::

    key-attributes = {
      ? extractable:       bool,
      ? never-extractable: bool,
      ? sensitive:         bool,
      ? local:             bool,
      ? purpose:           [* oid],
    }

The draft is deliberately silent on *where* those booleans come from — it only
speaks of an abstract "Attester". This module is the concrete bridge to a **TPM
2.0**: it derives ``key-attributes`` from the ``TPMA_OBJECT`` attribute bits of a
*certified* ``TPMT_PUBLIC`` (the public area a ``TPM2_Certify`` covered). Because
the attributes are read from the bytes the AK signed, the Attester cannot lie
about them — the mapping is the security-critical half of the whole design.

References
----------
draft-reddy-rats-key-binding-01 §3 (key-attributes), §5.2/§6 (RP policy)
TCG TPM 2.0 Library Part 2 §8.3 (TPMA_OBJECT), §12.2.4 (TPMT_PUBLIC)

"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# ── TPMA_OBJECT attribute bits (TPM 2.0 Part 2, Table 31) ────────────────────────
# Values verified against the installed tpm2-pytss enum, so they cannot drift.
FIXEDTPM = 0x00000002  # key can NEVER be duplicated out of this TPM
FIXEDPARENT = 0x00000010  # key cannot be re-parented (a precondition for duplication)
SENSITIVEDATAORIGIN = 0x00000020  # the TPM generated the private part (not imported)
USERWITHAUTH = 0x00000040  # USER-role actions authorized by the auth value
RESTRICTED = 0x00010000  # restricted key (signs/decrypts only TPM-internal data)
DECRYPT = 0x00020000  # usable for decryption
SIGN_ENCRYPT = 0x00040000  # usable for signing

#: ``objectAttributes`` is the UINT32 at byte offset 4 of a marshalled
#: ``TPMT_PUBLIC`` (immediately after ``type`` (2) and ``nameAlg`` (2)).
_OBJECT_ATTRIBUTES_OFFSET = 4


@dataclass(frozen=True)
class KeyAttributes:
    """A draft ``key-attributes`` value derived from one TPM object.

    Every field is a fact the TPM attested to via ``TPM2_Certify``; a Verifier
    that trusts the AK signature can trust these.
    """

    extractable: bool
    never_extractable: bool
    sensitive: bool
    local: bool
    purpose: tuple[str, ...]

    def to_claim(self) -> dict:
        """Return the draft §3 ``key-attributes`` map (exact member names)."""
        return {
            "extractable": self.extractable,
            "never-extractable": self.never_extractable,
            "sensitive": self.sensitive,
            "local": self.local,
            "purpose": list(self.purpose),
        }


def object_attributes_of(tpmt_public: bytes) -> int:
    """Return the raw ``TPMA_OBJECT`` UINT32 from a marshalled ``TPMT_PUBLIC``.

    :raises ValueError: if the buffer is too short to hold ``objectAttributes``.
    """
    if len(tpmt_public) < _OBJECT_ATTRIBUTES_OFFSET + 4:
        raise ValueError("TPMT_PUBLIC too short to contain objectAttributes")
    return struct.unpack_from(">I", tpmt_public, _OBJECT_ATTRIBUTES_OFFSET)[0]


def derive_key_attributes(tpmt_public: bytes) -> KeyAttributes:
    """Map a certified ``TPMT_PUBLIC``'s attributes to draft ``key-attributes``.

    This is the A1 Verifier step: the booleans come from the *certified* public
    area, so they reflect what the TPM enforces, not what the Attester claims.

    Mapping rationale (see the README for the full table):

    * ``never-extractable`` ← ``fixedTPM``  (private part never leaves this TPM)
    * ``extractable``       ← ``not fixedTPM``  (see below)
    * ``sensitive``         ← ``fixedTPM``  (private value never exposed in clear)
    * ``local``             ← ``sensitiveDataOrigin``  (TPM-generated, not imported)
    * ``purpose``           ← ``sign``/``decrypt`` from ``SIGN_ENCRYPT``/``DECRYPT``

    ``extractable`` is derived from ``fixedTPM``, **not** ``fixedParent``.
    ``fixedTPM`` is the *transitive* "never leaves this module" property (a key
    may only set it if its parent has it too), so it is the sound basis for
    extractability. ``fixedParent`` merely blocks direct re-parenting of one
    object: a key with ``fixedParent`` set but ``fixedTPM`` clear still lives
    under a duplicable parent and can be exfiltrated by duplicating that parent,
    so it must be reported ``extractable``.
    """
    attrs = object_attributes_of(tpmt_public)
    purpose: list[str] = []
    if attrs & SIGN_ENCRYPT:
        purpose.append("tpm:sign")
    if attrs & DECRYPT:
        purpose.append("tpm:decrypt")
    fixed_tpm = bool(attrs & FIXEDTPM)
    return KeyAttributes(
        extractable=not fixed_tpm,
        never_extractable=fixed_tpm,
        sensitive=fixed_tpm,
        local=bool(attrs & SENSITIVEDATAORIGIN),
        purpose=tuple(purpose),
    )


@dataclass(frozen=True)
class KeyBindingPolicy:
    """Relying-Party policy over the certified Subject Key (draft §5.2 / §6).

    The draft says a Relying Party that requires operational keys to live in an
    attested environment MUST check ``key-attributes``. This encodes such a
    policy; :meth:`check` returns the (possibly empty) list of violations.
    """

    require_never_extractable: bool = True
    forbid_extractable: bool = True
    require_local: bool = True
    require_purposes: tuple[str, ...] = ()

    def check(self, attrs: KeyAttributes) -> list[str]:
        """Return human-readable policy violations for *attrs* (empty == pass)."""
        errors: list[str] = []
        if self.require_never_extractable and not attrs.never_extractable:
            errors.append("policy requires never-extractable=true (TPM fixedTPM not set)")
        if self.forbid_extractable and attrs.extractable:
            errors.append("policy forbids extractable=true (TPM fixedTPM not set)")
        if self.require_local and not attrs.local:
            errors.append("policy requires local=true (TPM sensitiveDataOrigin not set)")
        for purpose in self.require_purposes:
            if purpose not in attrs.purpose:
                errors.append(f"policy requires key purpose {purpose!r}; certified purposes={list(attrs.purpose)}")
        return errors


__all__ = [
    "FIXEDTPM",
    "FIXEDPARENT",
    "SENSITIVEDATAORIGIN",
    "USERWITHAUTH",
    "RESTRICTED",
    "DECRYPT",
    "SIGN_ENCRYPT",
    "KeyAttributes",
    "KeyBindingPolicy",
    "derive_key_attributes",
    "object_attributes_of",
]
