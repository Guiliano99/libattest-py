from __future__ import annotations

from typing import Union

from pyasn1.codec.der import decoder as der_decoder
from pyasn1_alt_modules import rfc9480

from libattest.asn1_utils import try_decode_pyasn1
from libattest.formats.csrattest import NonceRequest, NonceResponse
from libattest.formats.stmt_mappings import (
    get_nonce_request_statement_structure,
    get_nonce_response_statement_structure,
)


def load_pki_message(data: Union[bytes, bytearray]) -> rfc9480.PKIMessage:
    """Load a PKIMessage (CMS ContentInfo) from DER-encoded bytes.

    Parameters
    ----------
    data : Union[bytes, bytearray]
        DER-encoded bytes representing a PKIMessage (CMS ContentInfo structure).

    Returns
    -------
    ContentInfo
        Decoded PKIMessage structure from RFC 5652.

    Raises
    ------
    ValueError
        If the data cannot be decoded as a valid PKIMessage.
    Exception
        If pyasn1 decoding fails.

    Examples
    --------
    >>> with open("message.der", "rb") as f:
    ...     pki_msg = load_pki_message(f.read())
    >>> print(pki_msg["contentType"])

    """
    try:
        decoded_msg, remainder = der_decoder.decode(bytes(data), asn1Spec=rfc9480.PKIMessage())
        if remainder:
            raise ValueError(f"Trailing bytes after PKIMessage: {len(remainder)} bytes remaining")
        return decoded_msg
    except Exception as exc:
        raise ValueError(f"Failed to decode PKIMessage: {exc}") from exc


def _decode_req_info(nonce_req: NonceRequest) -> object | None:
    """Auto-decode ``reqTypeInfo.reqInfo`` via ``stmt_mappings``, or ``None`` if absent.

    :raises ValueError: ``reqInfo`` is present but its ``type`` OID has no
        registered structure in ``NONCE_REQUEST_STATEMENT_STRUCTURES`` (see
        ``.claude/skills/libattest-py-update-stmt/SKILL.md``).
    """
    type_info = nonce_req["reqTypeInfo"]
    if not type_info.isValue or not type_info["reqInfo"].isValue:
        return None

    oid = type_info["type"]
    structure = get_nonce_request_statement_structure(oid)
    if structure is None:
        raise ValueError(
            f"No registered NONCE_REQUEST_STATEMENT_STRUCTURES entry for reqTypeInfo.type OID "
            f"{oid}; register it in stmt_mappings.py "
            f"(see .claude/skills/libattest-py-update-stmt/SKILL.md)."
        )
    raw = bytes(type_info["reqInfo"])
    return try_decode_pyasn1(raw, structure)


def _decode_resp_info(nonce_resp: NonceResponse) -> object | None:
    """Auto-decode ``respTypeInfo.respInfo`` via ``stmt_mappings``, or ``None`` if absent.

    :raises ValueError: ``respInfo`` is present but its ``type`` OID has no
        registered structure in ``NONCE_RESPONSE_STATEMENT_STRUCTURES`` (see
        ``.claude/skills/libattest-py-update-stmt/SKILL.md``).
    """
    type_info = nonce_resp["respTypeInfo"]
    if not type_info.isValue or not type_info["respInfo"].isValue:
        return None

    oid = type_info["type"]
    structure = get_nonce_response_statement_structure(oid)
    if structure is None:
        raise ValueError(
            f"No registered NONCE_RESPONSE_STATEMENT_STRUCTURES entry for respTypeInfo.type OID "
            f"{oid}; register it in stmt_mappings.py "
            f"(see .claude/skills/libattest-py-update-stmt/SKILL.md)."
        )
    return try_decode_pyasn1(bytes(type_info["respInfo"]), structure)


def parse_genm_pkimessage(data: bytes) -> rfc9480.PKIMessage:
    """Parse a genm PKIMessage, decode its NonceRequest, and auto-decode reqInfo in place.

    ``reqTypeInfo.reqInfo`` is overwritten with the fully decoded pyasn1
    structure selected by ``reqTypeInfo.type`` via
    ``stmt_mappings.NONCE_REQUEST_STATEMENT_STRUCTURES`` (left untouched when
    ``reqTypeInfo``/``reqInfo`` is absent), so a single
    ``nonce_request.prettyPrint()`` renders the whole message, evidence
    included. The returned structure is for display only — ``reqInfo`` no
    longer round-trips back to DER once overwritten.

    :raises ValueError: ``reqTypeInfo.reqInfo`` is present but its ``type`` OID
        has no registered structure (see :func:`_decode_req_info`).
    """
    pkimessage = load_pki_message(data)

    body_data = pkimessage["body"]["genm"][0]["infoValue"]
    nonce_req, _ = der_decoder.decode(body_data, asn1Spec=NonceRequest())
    pkimessage["body"]["genm"][0]["infoValue"] = nonce_req

    decoded_req_info = _decode_req_info(nonce_req)
    if decoded_req_info is not None:
        nonce_req["reqTypeInfo"]["reqInfo"] = decoded_req_info

    return pkimessage


def parse_genp_pkimessage(data: bytes) -> rfc9480.PKIMessage:
    """Parse a genp PKIMessage, decode its NonceResponse, and auto-decode respInfo in place.

    Loads a CMP PKIMessage with a genp (GenRepContent) body, extracts the first
    InfoTypeAndValue item's infoValue, decodes it as a NonceResponse structure,
    and overwrites ``respTypeInfo.respInfo`` with the fully decoded pyasn1
    structure selected by ``respTypeInfo.type`` via
    ``stmt_mappings.NONCE_RESPONSE_STATEMENT_STRUCTURES`` (left untouched when
    ``respTypeInfo``/``respInfo`` is absent), so a single
    ``nonce_response.prettyPrint()`` renders the whole message, evidence
    included. The returned structure is for display only — ``respInfo`` no
    longer round-trips back to DER once overwritten.

    Parameters
    ----------
    data : bytes
        DER-encoded PKIMessage containing a genp response with NonceResponse.

    Returns
    -------
    rfc9480.PKIMessage
        The decoded PKIMessage with the NonceResponse decoded in
        ``body["genp"][0]["infoValue"]`` and its ``respInfo`` replaced by the
        decoded structure.

    Raises
    ------
    ValueError
        ``respTypeInfo.respInfo`` is present but its ``type`` OID has no
        registered structure (see :func:`_decode_resp_info`).

    Examples
    --------
    >>> with open("rsp1-genp.der", "rb") as f:
    ...     pki_msg = parse_genp_pkimessage(f.read())
    >>> nonce_resp = pki_msg["body"]["genp"][0]["infoValue"]
    >>> print(nonce_resp.prettyPrint())

    """
    pkimessage = load_pki_message(data)

    body_data = pkimessage["body"]["genp"][0]["infoValue"]
    nonce_resp, _ = der_decoder.decode(body_data, asn1Spec=NonceResponse())
    pkimessage["body"]["genp"][0]["infoValue"] = nonce_resp

    decoded_resp_info = _decode_resp_info(nonce_resp)
    if decoded_resp_info is not None:
        nonce_resp["respTypeInfo"]["respInfo"] = decoded_resp_info

    return pkimessage


def parse_pkimessage(data: bytes) -> rfc9480.PKIMessage:
    """Parse a PKIMessage DER blob, auto-dispatching genm vs. genp bodies.

    Peeks at the decoded ``PKIBody``'s selected alternative
    (``body.getName()`` — ``"genm"`` or ``"genp"``) and routes to
    :func:`parse_genm_pkimessage` or :func:`parse_genp_pkimessage` accordingly.

    :raises ValueError: the body is neither ``genm`` nor ``genp``, or (via the
        delegated parse function) ``reqInfo``/``respInfo`` carries an
        unregistered OID.
    """
    pkimessage = load_pki_message(data)
    body_name = pkimessage["body"].getName()
    if body_name == "genm":
        return parse_genm_pkimessage(data)
    if body_name == "genp":
        return parse_genp_pkimessage(data)
    raise ValueError(f"parse_pkimessage: unsupported PKIBody type {body_name!r}; expected 'genm' or 'genp'.")
