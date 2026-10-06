# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Human-readable prettyPrint + debug logging for NXP attestation statements.

Three functions, nothing else.  Each one takes the *wire* form and does the
``OID`` + ``ASN.1`` parsing itself, so a caller never splits a statement by hand:

* :func:`pretty_print_statement`  — one ``AttestationStatement`` (DER or decoded)
* :func:`pretty_print_stmt_bundle` — an ``AttestationBundle``  (DER or decoded)
* :func:`log_statement_debug`     — the same, at ``DEBUG`` under
  ``libattest.formats.nxp`` (flip the verifier's log level and every appraised
  statement is inspectable in the service logs).

An ``AttestationStatement`` is ``{type OID, stmt ANY}``; the ``stmt`` of an NXP
statement is the opaque ``OCTET STRING`` (the NXP-native bytes).  The functions
decode the ASN.1, read the ``type`` OID, unwrap the ``OCTET STRING``, and render
with the matching codec.  The CA/RA never inspects the inner bytes — it only
routes on the OID.
"""

from __future__ import annotations

import logging
from typing import Union

from pyasn1.codec.der import decoder
from pyasn1.type import univ

from libattest.formats.csrattest.csr_attest_structures import (
    AttestationBundle,
    AttestationStatement,
    decode_attestation_bundle,
    decode_attestation_statement,
)
from libattest.formats.nxp.ele_dev_attest import (
    EleDevAttestError,
    decode_ele_dev_attest,
    pretty_print_ele_dev_attest,
)
from libattest.formats.nxp.ele_key_attest import (
    EleKeyAttestError,
    decode_ele_key_attest,
    pretty_print_ele_key_attest,
)
from libattest.formats.nxp.oid import (
    ELE_DEV_ATTEST_OID_DEFAULT,
    ELE_KEY_ATTEST_OID_DEFAULT,
    SE05X_ATTEST_OID_DEFAULT,
    resolve_ele_dev_attest_oid,
    resolve_ele_key_attest_oid,
    resolve_se05x_attest_oid,
)
from libattest.formats.nxp.se05x import (
    Se05xAttestError,
    decode_se05x_attest,
    pretty_print_se05x_attest,
)

logger = logging.getLogger("libattest.formats.nxp")

__all__ = [
    "pretty_print_statement",
    "pretty_print_stmt_bundle",
    "log_statement_debug",
]

# A statement OR a bundle, in wire (DER/bytearray) or decoded (pyasn1) form.
_Statement = Union[bytes, bytearray, univ.Any, AttestationStatement]
_Bundle = Union[bytes, bytearray, univ.Any, AttestationBundle]


# ── ASN.1 parsing helpers (the "do the OID + ASN.1 parsing" part) ─────────────

def _to_decoded_statement(stmt: _Statement) -> AttestationStatement:
    """Coerce a DER or decoded ``AttestationStatement`` to the decoded form."""
    if isinstance(stmt, AttestationStatement):
        return stmt
    return decode_attestation_statement(stmt)


def _to_decoded_bundle(bundle: _Bundle) -> AttestationBundle:
    """Coerce a DER or decoded ``AttestationBundle`` to the decoded form."""
    if isinstance(bundle, AttestationBundle):
        return bundle
    return decode_attestation_bundle(bundle)


def _stmt_oid(stmt: AttestationStatement) -> str:
    """The ``type`` OID of a decoded statement, as a dot-form string."""
    return str(stmt["type"])


def _stmt_payload(stmt: AttestationStatement) -> bytes:
    """The inner ``OCTET STRING`` bytes of ``stmt``.

    ``stmt`` is an ASN.1 open type.  For an opaque NXP statement its DER is an
    ``OCTET STRING`` (leading tag ``0x04``); that wrapper is stripped to return
    the raw NXP-native payload.  An ``stmt`` that is already a DER ASN.1
    structure (e.g. a SEQUENCE) is returned as-is.
    """
    b = bytes(stmt["stmt"])
    if b[:1] == b"\x04":  # OCTET STRING wrapper → unwrap
        return bytes(decoder.decode(b, univ.OctetString())[0])
    return b  # ASN.1 evidence: already the payload DER


def _first_component_tag(der: bytes) -> int | None:
    """Tag of the first component inside a top-level SEQUENCE, else ``None``."""
    if len(der) < 2 or der[0] != 0x30:  # must be a SEQUENCE
        return None
    i = 1
    if der[1] & 0x80:  # long-form length
        nlong = der[1] & 0x7F
        if nlong == 0 or i + 1 + nlong > len(der):
            return None
        i += 1 + nlong
    else:
        i += 1
    return der[i] if i < len(der) else None


def _looks_like_bundle(obj: _Statement | _Bundle) -> bool:
    """Distinguish an ``AttestationBundle`` from a single ``AttestationStatement``.

    Both are top-level SEQUENCEs, but their first component differs: a
    Statement starts with its ``type`` OID (tag ``0x06``); a Bundle starts with
    its ``attestations`` SEQUENCE OF (tag ``0x30``).  Decoded pyasn1 values are
    recognised by type first.
    """
    if isinstance(obj, AttestationBundle):
        return True
    if isinstance(obj, AttestationStatement):
        return False
    try:
        return _first_component_tag(bytes(obj)) == 0x30
    except Exception:
        return False


# ── render dispatch (OID → codec) ──────────────────────────────────────────────

def _render(oid: str, payload: bytes) -> str:
    """Render one NXP payload selected by its statement OID."""
    oid = str(oid)
    try:
        if oid in (resolve_ele_dev_attest_oid(), ELE_DEV_ATTEST_OID_DEFAULT):
            return pretty_print_ele_dev_attest(decode_ele_dev_attest(payload))
        if oid in (resolve_ele_key_attest_oid(), ELE_KEY_ATTEST_OID_DEFAULT):
            return pretty_print_ele_key_attest(decode_ele_key_attest(payload))
        if oid in (resolve_se05x_attest_oid(), SE05X_ATTEST_OID_DEFAULT):
            return pretty_print_se05x_attest(decode_se05x_attest(payload))
    except (EleDevAttestError, EleKeyAttestError, Se05xAttestError) as exc:
        return f"[{oid}] decode failed: {exc}"
    return f"[{oid}] no NXP codec registered for this statement OID"


# ── public API (three functions) ───────────────────────────────────────────────

def pretty_print_statement(stmt: _Statement) -> str:
    """PrettyPrint one ``AttestationStatement``, doing the parsing itself.

    ``stmt`` may be the DER bytes of an ``AttestationStatement`` (or
    ``bytearray``/pyasn1 ``Any``) or an already-decoded ``AttestationStatement``.
    The function decodes the ASN.1, reads the ``type`` OID, unwraps the ``stmt``
    ``OCTET STRING``, and renders it with the matching NXP codec.

    >>> from libattest.formats.nxp import pretty_print_statement
    >>> print(pretty_print_statement(stmt_der))
    """
    s = _to_decoded_statement(stmt)
    return _render(_stmt_oid(s), _stmt_payload(s))


def pretty_print_stmt_bundle(bundle: _Bundle) -> str:
    """PrettyPrint every statement of an ``AttestationBundle``.

    ``bundle`` may be DER bytes (or ``bytearray``/pyasn1 ``Any``) or an
    already-decoded ``AttestationBundle``.  Statements are rendered in order and
    joined by a blank line; each does its own OID + ASN.1 parsing.
    """
    b = _to_decoded_bundle(bundle)
    statements = list(b["attestations"] or [])
    blocks = [pretty_print_statement(s) for s in statements]
    if not blocks:
        return "[bundle] no statements"
    return "\n\n".join(blocks)


def log_statement_debug(stmt_or_bundle: _Statement | _Bundle, extra: str = "") -> None:
    """Log a human-readable dump at ``DEBUG`` under ``libattest.formats.nxp``.

    ``stmt_or_bundle`` may be a single ``AttestationStatement`` or a whole
    ``AttestationBundle`` (either in DER or decoded form).  A bundle logs every
    statement.  ``extra`` is appended to the leading line (e.g. ``gate=G2``).
    """
    text = (
        pretty_print_stmt_bundle(stmt_or_bundle)
        if _looks_like_bundle(stmt_or_bundle)
        else pretty_print_statement(stmt_or_bundle)
    )
    suffix = f" {extra}" if extra else ""
    logger.debug("NXP statement%s:\n%s", suffix, text)
