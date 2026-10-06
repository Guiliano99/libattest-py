# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Human-readable prettyPrint + debug logging for NXP attestation statements.

Single entry point :func:`pretty_print_nxp_statement` keys on the statement
OID (the same OID the CA/RA routes on) so a bundle's statements can be dumped
without the caller knowing the format:

    >>> from libattest.formats.nxp import pretty_print_nxp_statement
    >>> print(pretty_print_nxp_statement(oid, stmt_bytes))

Also exposes :func:`log_statement_debug`, which emits the full prettyPrint at
``DEBUG`` level under the ``libattest.formats.nxp`` logger — flip the verifier's
log level to debug and every appraised NXP statement is inspectable in the
service logs.
"""

from __future__ import annotations

import logging
from typing import Iterable

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
    "pretty_print_nxp_statement",
    "pretty_print_nxp_bundle",
    "log_statement_debug",
]


def _decode_and_render(oid: str, payload: bytes) -> str:
    oid = str(oid)
    try:
        if oid == resolve_ele_dev_attest_oid() or oid == ELE_DEV_ATTEST_OID_DEFAULT:
            return pretty_print_ele_dev_attest(decode_ele_dev_attest(payload))
        if oid == resolve_ele_key_attest_oid() or oid == ELE_KEY_ATTEST_OID_DEFAULT:
            return pretty_print_ele_key_attest(decode_ele_key_attest(payload))
        if oid == resolve_se05x_attest_oid() or oid == SE05X_ATTEST_OID_DEFAULT:
            return pretty_print_se05x_attest(decode_se05x_attest(payload))
    except (EleDevAttestError, EleKeyAttestError, Se05xAttestError) as exc:
        return f"[{oid}] decode failed: {exc}"
    return f"[{oid}] no NXP codec registered for this statement OID"


def pretty_print_nxp_statement(oid: str, payload: bytes) -> str:
    """PrettyPrint one NXP statement payload, selected by its statement OID.

    ``payload`` is the opaque ``OCTET STRING`` bytes of an
    ``AttestationStatement.stmt`` (already unwrapped from the DER envelope).
    """
    return _decode_and_render(oid, bytes(payload))


def pretty_print_nxp_bundle(bundle, all_statements: bool = True) -> str:
    """PrettyPrint every NXP statement of a decoded ``AttestationBundle``.

    *bundle* is the pyasn1 structure returned by
    ``libattest.formats.csrattest.decode_attestation_bundle``.  Non-NXP
    statements are listed by OID (not expanded) unless they decode.
    """
    blocks: list[str] = []
    for stmt in bundle.get("attestations") or []:
        oid = str(stmt.get("type"))
        raw = bytes(stmt.get("stmt"))
        blocks.append(pretty_print_nxp_statement(oid, raw))
    return "\n\n".join(blocks)


def log_statement_debug(oid: str, payload: bytes, extra: str = "") -> None:
    """Log the prettyPrinted statement at DEBUG level (verifier-side hook)."""
    suffix = f" {extra}" if extra else ""
    logger.debug(
        "NXP statement oid=%s (%dB)%s:\n%s",
        oid,
        len(payload),
        suffix,
        pretty_print_nxp_statement(oid, payload),
    )
