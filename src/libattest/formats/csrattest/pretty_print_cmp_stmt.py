from __future__ import annotations

from typing import Union

from pyasn1.codec.der import decoder as der_decoder
from pyasn1_alt_modules import rfc9480

from libattest.formats.csrattest import NonceRequest, NonceResponse


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


def parse_genm_pkimessage(data: bytes) -> rfc9480.PKIMessage:
    """Parse a PKIMessage (CMS ContentInfo) from a file."""
    pkimessage = load_pki_message(data)

    data = pkimessage["body"]["genm"][0]["infoValue"]
    nonce_req, _ = der_decoder.decode(data, asn1Spec=NonceRequest())
    pkimessage["body"]["genm"][0]["infoValue"] = nonce_req
    return pkimessage


def parse_genp_pkimessage(data: bytes) -> rfc9480.PKIMessage:
    """Parse a genp PKIMessage and decode NonceResponse.

    Loads a CMP PKIMessage with a genp (GenRepContent) body, extracts the first
    InfoTypeAndValue item's infoValue, and decodes it as a NonceResponse structure.

    Parameters
    ----------
    data : bytes
        DER-encoded PKIMessage containing a genp response with NonceResponse.

    Returns
    -------
    rfc9480.PKIMessage
        The decoded PKIMessage with the NonceResponse decoded in body["genp"][0]["infoValue"].

    Examples
    --------
    >>> with open("rsp1-genp.der", "rb") as f:
    ...     pki_msg = parse_genp_pkimessage(f.read())
    >>> nonce_resp = pki_msg["body"]["genp"][0]["infoValue"]
    >>> print(nonce_resp["nonce"].prettyPrint())

    """
    pkimessage = load_pki_message(data)

    data = pkimessage["body"]["genp"][0]["infoValue"]
    nonce_resp, _ = der_decoder.decode(data, asn1Spec=NonceResponse())
    pkimessage["body"]["genp"][0]["infoValue"] = nonce_resp
    return pkimessage
