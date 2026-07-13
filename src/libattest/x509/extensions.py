# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""X.509 extensions used by libattest.

Currently exposes:

* The Conceptual Messages Wrapper (CMW) extension defined in
  :rfc-draft:`draft-ietf-rats-msg-wrap-23` §4.4 — see :class:`CMW` and
  :func:`parse_cmw_extension_value`.

CMW is non-critical per draft §4.4.6.

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

import base64
import json
import logging
import warnings
from typing import Optional, Union

from pyasn1.codec.der import decoder as _der_decoder
from pyasn1.codec.der import encoder as _der_encoder
from pyasn1.type import char, namedtype, univ

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


# ── EAR extension encoding (CMW vs raw JWT) ──────────────────────────────────


def wrap_ear_in_cmw_json(ear_jwt: str) -> bytes:
    """Return the DER extnValue content for an ``id-pe-cmw`` EAR extension.

    Builds a CMW (Conceptual Message Wrapper) JSON *record*
    ``[media-type, base64url-nopad(message)]`` (draft-ietf-rats-msg-wrap-23 §3)
    and carries it in the CMW ``json`` (UTF8String) alternative (§4.4).  The
    value field is base64url-encoded without padding even though a JWT is
    already textual, exactly as the draft requires.

    The returned bytes are the DER of the :class:`CMW` CHOICE, ready to be
    placed verbatim into an X.509 ``Extension.extnValue`` OCTET STRING.
    """
    value_b64 = base64.urlsafe_b64encode(ear_jwt.encode("utf-8")).decode("ascii").rstrip("=")
    record = json.dumps(["application/eat+jwt", value_b64], separators=(",", ":"))
    cmw = CMW()
    cmw.setComponentByName("json", char.UTF8String(record))
    return _der_encoder.encode(cmw)


def encode_cmw_json_record(media_type: str, value: str, cmw_type: int | None = None) -> bytes:
    """Return the DER of a CMW ``json`` record ``[media-type, value(, cmw-type)]``.

    A generic CMW (Conceptual Message Wrapper) JSON *record*
    (draft-ietf-rats-msg-wrap-23 §3) carried in the CMW ``json`` (UTF8String)
    alternative (§4.4).  Unlike :func:`wrap_ear_in_cmw_json`, *value* is placed
    verbatim — callers pass an already-serialised message (e.g. a compact JOSE
    JWE string).  ``cmw_type`` adds the optional third element (the CMW type
    indicator, e.g. ``4``).  The result is wire-identical to encoding the bare
    ``UTF8String`` (a CHOICE encodes as its selected alternative in DER).
    """
    record = [media_type, value] if cmw_type is None else [media_type, value, cmw_type]
    cmw = CMW()
    cmw.setComponentByName("json", char.UTF8String(json.dumps(record, separators=(",", ":"))))
    return _der_encoder.encode(cmw)


def decode_cmw_json_record(der: bytes) -> tuple[str, str, Optional[int]]:
    """Decode a CMW ``json`` record DER into ``(media_type, value, cmw_type)``.

    Accepts the DER of the :class:`CMW` CHOICE (or, wire-identically, a bare
    ``UTF8String``).  Returns ``cmw_type`` as ``None`` when the record carries
    only the two mandatory elements.

    :raises ValueError: the bytes are not a CMW ``json`` record / malformed JSON.
    """
    cmw, _ = _der_decoder.decode(der, asn1Spec=CMW())
    if cmw.getName() != "json":
        raise ValueError("CMW is not a json record (expected the UTF8String alternative)")
    record = json.loads(str(cmw["json"]))
    if not isinstance(record, list) or len(record) < 2:
        raise ValueError(f"malformed CMW json record: {record!r}")
    cmw_type = record[2] if len(record) > 2 else None
    return record[0], record[1], cmw_type


def encode_ear_extension(ear_jwt: str, *, oid: str) -> tuple[str, bytes]:
    """Encode an EAR JWT into an X.509 extension ``(oid, extn_value_der)`` pair.

    Selects the extension value encoding from *oid*:

    * ``oid == id-pe-cmw`` (``1.3.6.1.5.5.7.1.35``) → the value is a CMW JSON
      record wrapping the EAR JWT (draft-ietf-rats-msg-wrap-23 §4.4), produced by
      :func:`wrap_ear_in_cmw_json`.
    * any other *oid* (e.g. a demo/private OID) → the value is the raw EAR JWT
      bytes (``ear_jwt.encode("utf-8")``), placed verbatim.

    Parameters
    ----------
    ear_jwt:
        The compact-serialised EAR JWT string.
    oid:
        The dot-form OID under which the extension will be embedded.

    Returns
    -------
    tuple[str, bytes]
        ``(oid, extn_value_der)`` — the *oid* echoed back (so callers can use
        this as the single source of the extension OID) and the DER-encoded
        extension value content.

    """
    if oid == ID_PE_CMW_DOTTED:
        return oid, wrap_ear_in_cmw_json(ear_jwt)
    return oid, ear_jwt.encode("utf-8")


def unwrap_context_tag(der: bytes) -> bytes:
    """Strip one outer context-specific tag from *der*, if present.

    pyasn1 components extracted from a tagged CHOICE (e.g.
    ``CertOrEncCert.certificate``) re-encode with the context tag attached.
    For an EXPLICIT tag the inner TLV is returned verbatim; for an IMPLICIT
    tag the outer tag byte is rewritten to SEQUENCE (``0x30``).

    This is a pure byte-level helper (no ASN.1 decode) so callers that only
    need a plain ``Certificate`` TLV out of a CHOICE re-encoding can reuse it.
    """
    if not der or der[0] == 0x30:
        return der
    # Skip the outer tag + length octets.
    idx = 1
    first_len = der[idx]
    idx += 1
    if first_len & 0x80:
        idx += first_len & 0x7F
    inner = der[idx:]
    if inner and inner[0] == 0x30:
        return inner  # EXPLICIT tag: inner TLV is the full SEQUENCE
    return b"\x30" + der[1:]  # IMPLICIT tag: retag as SEQUENCE
