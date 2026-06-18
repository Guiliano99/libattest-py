# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""X.509 extensions used by libattest.

Currently exposes:

* The Conceptual Messages Wrapper (CMW) extension defined in
  :rfc-draft:`draft-ietf-rats-msg-wrap-23` §4.4 — see :class:`CMW` and
  :func:`parse_cmw_extension_value`.
* The KeyAttestPoP extension — an X.509 v3 extension whose OID is
  :func:`resolve_key_attest_pop_oid` and whose value is a DER-encoded
  :class:`~libattest.formats.key_attest_pop.KeyAttestPoP`.

CMW is non-critical per draft §4.4.6.  ``KeyAttestPoP`` criticality is selected
by the certificate profile.

CMW (draft-ietf-rats-msg-wrap-23 §4.4)
--------------------------------------

ASN.1 module (verbatim from the draft)
--------------------------------------
::

    id-pe-cmw  OBJECT IDENTIFIER ::=
        { iso(1) identified-organization(3) dod(6) internet(1)
          security(5) mechanisms(5) pkix(7) id-pe(1) 35 }

    CMW ::= CHOICE {
        json UTF8String,
        cbor OCTET STRING
    }

Module header is ``IMPLICIT TAGS``, but the two CHOICE alternatives carry
no explicit per-alternative tags — pyasn1 disambiguates by the underlying
universal tag (UTF8String 0x0C vs OCTET STRING 0x04).

The DER encoding of the CMW value is placed verbatim in the
X.509 ``Extension.extnValue`` OCTET STRING; that is the standard X.509
extension wrapping and is handled by whatever ASN.1 library builds the
certificate (pyasn1, cryptography, OpenSSL).

Criticality
-----------
The draft (§4.4.6) says:

  *"This extension SHOULD NOT be marked critical.  In cases where the
  wrapped Conceptual Message is essential for granting resource access,
  and there is a risk that legacy relying parties would bypass crucial
  controls, it is acceptable to mark the extension as critical."*

This module exposes :func:`warn_if_cmw_critical` /
:func:`validate_cmw_extension` to surface a warning whenever the
extension is encountered with the ``critical`` bit set; the warning does
not fail the parse, in line with the SHOULD NOT (rather than MUST NOT)
wording in the draft.
"""

from __future__ import annotations

import logging
import warnings
from typing import Optional, Union

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.type import char, namedtype, univ

from libattest.formats.key_attest_pop.structures import (
    KeyAttestPoP,
    decode_key_attest_pop,
    resolve_key_attest_pop_oid,
)

logger = logging.getLogger(__name__)

# ── OID constants ────────────────────────────────────────────────────────────

#: ``id-pe-cmw`` as a pyasn1 :class:`~pyasn1.type.univ.ObjectIdentifier`.
ID_PE_CMW: univ.ObjectIdentifier = univ.ObjectIdentifier("1.3.6.1.5.5.7.1.35")

#: ``id-pe-cmw`` as a Python string in dot-decimal form.  Useful when
#: matching against ``cryptography.x509.Extension.oid.dotted_string`` or
#: ``str(asn1_obj)`` output from pyasn1.
ID_PE_CMW_DOTTED: str = "1.3.6.1.5.5.7.1.35"


# ── ASN.1 schema ─────────────────────────────────────────────────────────────


class CMW(univ.Choice):
    """``CMW ::= CHOICE { json UTF8String, cbor OCTET STRING }``.

    Use as a pyasn1 ``asn1Spec`` to decode a CMW extension value::

        cmw, _ = pyasn1.codec.der.decoder.decode(extn_value_bytes, asn1Spec=CMW())
        if cmw.getName() == "json":
            payload = str(cmw["json"]).encode("utf-8")
        else:
            payload = bytes(cmw["cbor"])

    Construction for encoding follows the same pattern::

        cmw = CMW()
        cmw.setComponentByName("cbor", univ.OctetString(my_cbor_bytes))
        der = pyasn1.codec.der.encoder.encode(cmw)
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("json", char.UTF8String()),
        namedtype.NamedType("cbor", univ.OctetString()),
    )


# ── Criticality validation ───────────────────────────────────────────────────


class CMWCriticalityWarning(UserWarning):
    """Warning category emitted when a CMW extension is marked critical.

    Subclassing :class:`UserWarning` lets test code catch the warning with
    ``warnings.catch_warnings`` and assert on it without coupling to the
    log subsystem.  Programmatic consumers that want this to be fatal can
    promote it to an error::

        warnings.filterwarnings("error", category=CMWCriticalityWarning)
    """


def warn_if_cmw_critical(critical: bool) -> None:
    """Emit a warning (and a log message) when *critical* is True.

    Non-fatal: the draft says the extension SHOULD NOT be critical, not
    MUST NOT.  Callers that want a hard rejection should either:

    * promote the warning category to an error via
      ``warnings.filterwarnings("error", category=CMWCriticalityWarning)``, or
    * call :func:`validate_cmw_extension` and raise on the returned bool.
    """
    if critical:
        msg = (
            "CMW (id-pe-cmw, 1.3.6.1.5.5.7.1.35) extension is marked critical; "
            "draft-ietf-rats-msg-wrap-23 §4.4.6 says it SHOULD NOT be critical."
        )
        logger.warning(msg)
        warnings.warn(msg, category=CMWCriticalityWarning, stacklevel=2)


# ── Parse / validate helpers ─────────────────────────────────────────────────


def parse_cmw_extension_value(extn_value: bytes) -> CMW:
    """Decode the DER content of an X.509 ``Extension.extnValue`` into a CMW.

    *extn_value* is the OCTET STRING payload — i.e., what
    ``cryptography.x509.Extension.value`` returns as ``.public_bytes()`` for
    an UnrecognizedExtension, or what pyasn1 yields as the raw bytes of
    ``Extension.extnValue``.  It MUST be the DER of the CMW SEQUENCE
    contents (no outer OCTET STRING wrapper).

    :raises ValueError: when the bytes do not decode as a CMW CHOICE.
    """
    try:
        decoded, _trailing = _der_decoder.decode(extn_value, asn1Spec=CMW())
    except Exception as exc:  # noqa: BLE001 — pyasn1 raises various concrete types
        raise ValueError(f"failed to decode CMW: {exc}") from exc
    return decoded  # type: ignore[return-value]


def validate_cmw_extension(
    critical: bool,
    extn_value: Optional[Union[bytes, CMW]] = None,
) -> bool:
    """Validate a CMW extension's metadata and (optionally) its content.

    Currently:

    * Calls :func:`warn_if_cmw_critical` to surface a non-fatal warning
      when the extension is marked critical.
    * If *extn_value* is provided as bytes, attempts to decode it as a CMW
      and returns False on decode failure.
    * If *extn_value* is provided as a parsed :class:`CMW`, no decode is
      attempted.

    :param critical: the X.509 ``critical`` flag of the extension.
    :param extn_value: optional content to sanity-check; either raw DER
        bytes (decoded via :func:`parse_cmw_extension_value`) or an
        already-parsed :class:`CMW` instance.
    :return: ``True`` when the extension's structure is well-formed (or
        when *extn_value* was not supplied), ``False`` when content
        decoding failed.  Note this return value does NOT reflect the
        criticality warning — that is reported via :mod:`warnings` and the
        logger.
    """
    warn_if_cmw_critical(critical)

    if extn_value is None or isinstance(extn_value, CMW):
        return True

    try:
        parse_cmw_extension_value(extn_value)
    except ValueError as exc:
        logger.warning("CMW content decode failed: %s", exc)
        return False
    return True


# ── KeyAttestPoP extension (SPEC §DR-1, §DR-8) ──────────────────────────────


def get_key_attest_pop_oid_dotted() -> str:
    """Return the dotted-string OID for the KeyAttestPoP extension.

    Resolved on demand from :envvar:`KEY_ATTEST_POP_OID` so docker-compose
    overrides take effect without a re-import.
    """
    return resolve_key_attest_pop_oid()


def get_key_attest_pop_oid() -> univ.ObjectIdentifier:
    """Return the KeyAttestPoP OID as a pyasn1 :class:`ObjectIdentifier`.

    Computed lazily from the env-resolved dotted form.
    """
    return univ.ObjectIdentifier(resolve_key_attest_pop_oid())


#: Module-level alias for the env-resolved dotted OID.  Convenient for
#: matching against ``cryptography.x509.Extension.oid.dotted_string``;
#: callers that need to react to env changes at runtime should call
#: :func:`get_key_attest_pop_oid_dotted` instead.
ID_KEY_ATTEST_POP_DOTTED: str = resolve_key_attest_pop_oid()

#: Module-level alias for the env-resolved OID as a pyasn1 OID.
ID_KEY_ATTEST_POP: univ.ObjectIdentifier = univ.ObjectIdentifier(ID_KEY_ATTEST_POP_DOTTED)


class KeyAttestPoPCriticalityWarning(UserWarning):
    """Warning category emitted when the KeyAttestPoP extension is critical.

    Some profiles mark this private extension critical so legacy clients cannot ignore it.
    Subclasses :class:`UserWarning` so test code can promote to error via
    ``warnings.filterwarnings("error", ...)``.
    """


def warn_if_key_attest_pop_critical(critical: bool) -> None:
    """Emit a warning when the KeyAttestPoP extension is marked critical."""
    if critical:
        msg = (
            f"KeyAttestPoP ({ID_KEY_ATTEST_POP_DOTTED}) extension is marked "
            "critical. This is allowed only when the certificate profile "
            "requires legacy clients to reject requests that do not understand it."
        )
        logger.warning(msg)
        warnings.warn(msg, category=KeyAttestPoPCriticalityWarning, stacklevel=2)


def parse_key_attest_pop_extension_value(extn_value: bytes) -> KeyAttestPoP:
    """Decode the DER content of a KeyAttestPoP ``Extension.extnValue``.

    *extn_value* is the OCTET STRING payload — i.e., what
    :class:`cryptography.x509.UnrecognizedExtension.value` returns, or
    what ``pyasn1`` yields as the raw bytes of ``Extension.extnValue``.
    The bytes MUST be the DER of a
    :class:`~libattest.formats.key_attest_pop.KeyAttestPoP` SEQUENCE.

    :raises ValueError: when the bytes do not decode as a
        ``KeyAttestPoP``.
    """
    return decode_key_attest_pop(extn_value)


def validate_key_attest_pop_extension(
    critical: bool,
    extn_value: Optional[Union[bytes, KeyAttestPoP]] = None,
) -> bool:
    """Validate a KeyAttestPoP extension's metadata and (optionally) content.

    Mirrors :func:`validate_cmw_extension`:

    * Calls :func:`warn_if_key_attest_pop_critical` to surface a
      non-fatal warning when ``critical=True``.
    * If *extn_value* is bytes, attempts to decode it as a
      ``KeyAttestPoP`` and returns ``False`` on failure.
    * If *extn_value* is already a parsed ``KeyAttestPoP``, no
      decode is attempted.

    :param critical: the X.509 ``critical`` flag of the extension.
    :param extn_value: optional content to sanity-check.
    :returns: ``True`` when the extension is well-formed (or no content
        was supplied); ``False`` when content decoding failed.  The
        return value does NOT reflect the criticality warning.
    """
    warn_if_key_attest_pop_critical(critical)

    if extn_value is None or isinstance(extn_value, KeyAttestPoP):
        return True

    try:
        parse_key_attest_pop_extension_value(extn_value)
    except ValueError as exc:
        logger.warning("KeyAttestPoP content decode failed: %s", exc)
        return False
    return True
