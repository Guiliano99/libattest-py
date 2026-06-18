# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""PCR reference-value structures for TPM platform attestation appraisal.

These structures define the expected platform state against which the
``pcrDigest`` in a ``TPMS_QUOTE_INFO`` is compared.  They are intentionally
kept format-agnostic so they can be loaded from JSON, YAML, or constructed
programmatically in test code.

Example JSON file (set ``PCR_REFERENCE_VALUES_FILE`` env var to the path)::

    {"description": "Golden boot state — firmware v1.2, kernel 6.1", "expected_pcr_digest_hex": "aabbcc..."}

Obtain ``expected_pcr_digest_hex`` by running a known-good attestation and
capturing the quoted ``pcrDigest`` from the tpm-verifier log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class PcrReferenceValues:
    """Expected PCR state for a trusted platform configuration.

    Attributes
    ----------
    expected_pcr_digest_hex:
        Hex-encoded expected ``pcrDigest`` from ``TPMS_QUOTE_INFO``.
        When set, :func:`verify_pcr_quote` compares the quoted digest
        directly against this value.
    description:
        Human-readable label for this reference set (logged on mismatch).

    """

    expected_pcr_digest_hex: str | None = None
    description: str = ""


def load_pcr_reference_values(path: str) -> PcrReferenceValues:
    """Load :class:`PcrReferenceValues` from a JSON file.

    Expected schema::

        {"description": "string (optional)", "expected_pcr_digest_hex": "hexstring"}

    Parameters
    ----------
    path:
        Filesystem path to the JSON configuration file.

    Returns
    -------
    PcrReferenceValues

    Raises
    ------
    OSError
        If the file cannot be opened.
    ValueError
        If the JSON is malformed or contains invalid hex.

    """
    with open(path) as fh:
        data = json.load(fh)
    hex_val = data.get("expected_pcr_digest_hex")
    if hex_val is not None:
        # Validate hex string eagerly so callers get a clear error at load time.
        try:
            bytes.fromhex(hex_val)
        except ValueError as exc:
            raise ValueError(f"expected_pcr_digest_hex in {path!r} is not valid hex: {exc}") from exc
    return PcrReferenceValues(
        expected_pcr_digest_hex=hex_val,
        description=data.get("description", ""),
    )


def verify_pcr_quote(
    pcr_selections: list[dict],
    pcr_digest: bytes,
    reference: PcrReferenceValues,
) -> tuple[bool, str]:
    """Compare a quoted ``pcrDigest`` against :class:`PcrReferenceValues`.

    Parameters
    ----------
    pcr_selections:
        PCR selection list from a parsed
        :class:`~libattest.formats.tpm.tpms_attest.ParsedAttest`.
        Used only for diagnostic logging; the comparison is on ``pcr_digest``.
    pcr_digest:
        Raw bytes of ``TPMS_QUOTE_INFO.pcrDigest`` (from TPM2B_DIGEST).
    reference:
        Expected reference state.

    Returns
    -------
    tuple[bool, str]
        ``(True, reason)`` when the digest matches the reference,
        ``(False, reason)`` otherwise.

    """
    if reference.expected_pcr_digest_hex is None:
        return False, "no reference PCR digest configured in PcrReferenceValues"

    expected = bytes.fromhex(reference.expected_pcr_digest_hex)
    if pcr_digest == expected:
        return (
            True,
            f"pcrDigest matches reference ({len(pcr_selections)} PCR selection(s))"
            + (f" [{reference.description}]" if reference.description else ""),
        )
    return (
        False,
        "pcrDigest mismatch"
        + (f" ({reference.description})" if reference.description else "")
        + f": expected={expected.hex()} got={pcr_digest.hex()}",
    )
