# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""i.MX ELE key-attest statement codec (``hsm_pub_key_attest``, SAB 0x74).

``hsm_pub_key_attest`` returns the attested key as a **signed EdgeLock 2GO-TLV
certificate buffer** (``op_pub_key_attest_args_t.certificate`` /
``certificate_size``, RM00284 Rev. 4.5 §3.4.2.1).  This is the proof that the
enrolled subject key is the one the SoC attests — the analogue of a TPM
``TPM2_Certify`` certified-key public.

The 2GO-TLV tag semantics for the *output* key-attest certificate are not
published verbatim in the open material I can cite, so this codec is
**format-agnostic by design**: it walks every TLV and decodes the well-known
EdgeLock tag names where they are unambiguous, surfacing unknown tags verbatim
(never dropped).  That keeps the human prettyPrint faithful and makes a future
tag-map correction a one-line change rather than a data-loss bug.

The attester binds freshness by passing ``auth_challenge`` = the RA nonce into
``op_pub_key_attest_args_t``; the certificate signature covers it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from libattest.formats.nxp.tlv import TlvEntry, parse_tlvs

logger = logging.getLogger("libattest.formats.nxp.ele_key_attest")

__all__ = [
    "EleKeyAttestStatement",
    "EleKeyAttestError",
    "decode_ele_key_attest",
    "pretty_print_ele_key_attest",
    "KNOWN_2GO_TAGS",
]


class EleKeyAttestError(ValueError):
    """Raised when a key-attest certificate buffer cannot be parsed."""


#: Best-effort, unambiguous EdgeLock TLV tag names.  Unknown tags are kept as
#: ``0xNN`` and never silently dropped (see module docstring).
KNOWN_2GO_TAGS: dict[int, str] = {
    0x01: "issuer",
    0x02: "subject",
    0x03: "subject_public_key_info",
    0x04: "serial_number",
    0x05: "validity_not_before",
    0x06: "validity_not_after",
    0x07: "signature_algorithm",
    0x08: "signature_value",
    0x09: "attest_algo",
    0x0A: "auth_challenge",
    0x0B: "key_identifier",
    0x0C: "key_attestation_id",
}


@dataclass
class EleKeyAttestStatement:
    """Decoded 2GO-TLV key-attest certificate buffer."""

    entries: list[TlvEntry] = field(default_factory=list)
    raw: bytes = field(repr=False, default=b"")

    # ── lookups ────────────────────────────────────────────────────────────
    def value(self, tag: int) -> bytes | None:
        """Return the value of *tag* (first occurrence) or ``None``."""
        for e in self.entries:
            if e.tag == tag:
                return e.value
        return None

    def has(self, tag: int) -> bool:
        return any(e.tag == tag for e in self.entries)

    def named(self, tag: int) -> str:
        return KNOWN_2GO_TAGS.get(tag, f"unknown(0x{tag:02X})")

    def verify_signature(self, pubkey) -> bool:  # pragma: no cover - cert sig TBD
        raise NotImplementedError(
            "2GO-TLV certificate signature verification requires the "
            "attestation-key trust anchor + exact signed-byte layout; see module docstring"
        )

    def pretty(self) -> str:
        return pretty_print_ele_key_attest(self)


def decode_ele_key_attest(raw: bytes) -> EleKeyAttestStatement:
    """Parse a 2GO-TLV key-attest certificate buffer into a structured object.

    :raises EleKeyAttestError: if the buffer is empty or not a valid TLV stream.
    """
    if not raw:
        raise EleKeyAttestError("key-attest certificate buffer is empty")
    try:
        entries = parse_tlvs(raw)
    except ValueError as exc:
        raise EleKeyAttestError(f"not a valid 2GO-TLV stream: {exc}") from exc
    logger.debug("decoded ELE key-attest: %d TLVs, %dB", len(entries), len(raw))
    return EleKeyAttestStatement(entries=entries, raw=raw)


def pretty_print_ele_key_attest(stmt: EleKeyAttestStatement) -> str:
    """Render the 2GO-TLV key-attest certificate as a readable block."""
    lines = [
        f"ELE key-attest certificate (2GO-TLV, {len(stmt.raw)} B, {len(stmt.entries)} TLVs)",
    ]
    for e in stmt.entries:
        name = stmt.named(e.tag)
        v = e.value
        # Heuristic: render short integer-ish values as hex, long as hex dump.
        if len(v) <= 8:
            shown = v.hex()
        else:
            shown = v.hex()
            if len(v) > 48:
                shown = v[:48].hex() + f"... (+{len(v) - 48}B)"
        lines.append(f"  [off {e.offset:3d}] 0x{e.tag:02X} {name:<22} {shown}")
    return "\n".join(lines)


def __getattr__(name):
    if name == "pretty_print_ele_key_attest":
        return pretty_print_ele_key_attest
    raise AttributeError(name)
