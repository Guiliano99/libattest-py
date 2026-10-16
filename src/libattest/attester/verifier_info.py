# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""What the attester learns about the verifier before it produces any Evidence.

The RA answers a ``NonceRequest`` with a ``NonceResponse`` that carries more than a
nonce: ``respTypeInfo.type`` names a syntax and ``respTypeInfo.respInfo`` carries the
verifier information encoded in it — the PCR set and hash algorithm the RA promises to
appraise, the credential-activation challenge, or the HPKE recipient key the Evidence
must be encrypted to.  Until now every attester read that field itself, each one
hardcoding the single syntax it happened to care about; an attester that met a second
profile had no way to ask *what did the verifier tell me* without knowing in advance.

:class:`VerifierInfo` is that question with one answer.  Parsing is deliberately split
in two: the container is decoded eagerly (a malformed ``NonceResponse`` is an error at
the point of receipt), while the ``respInfo`` payload is interpreted **on demand** by an
accessor that knows its syntax.  An attester therefore never has to decode a payload it
does not understand, and meeting an unknown ``respTypeInfo.type`` degrades to "this
exchange carries no information I can use" instead of an exception.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec

from libattest import get_nonce_response_oid_for_name
from libattest.asn1_utils import try_decode_pyasn1
from libattest.formats.csrattest import NonceResponse, nonce_response_info, nonce_response_type_oid
from libattest.formats.eareat_hpke import hpke_key_from_spki_der

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class VerifierInfo:
    """The verifier information one ``NonceResponse`` provisions to the attester.

    Attributes
    ----------
    nonce:
        The RA-issued freshness nonce the Evidence must be bound to.  Empty means the
        RA asked for no freshness proof.
    response_type_oid:
        Dot-form ``respTypeInfo.type`` — the syntax selector for :attr:`resp_info`.
        ``None`` when the response carries no type at all.
    resp_info:
        Raw DER of ``respTypeInfo.respInfo``, uninterpreted.  ``None`` when the
        exchange negotiates nothing.
    expiry:
        ``NonceResponse.expiry`` in seconds, when the RA advertised one — how long the
        attester has before the nonce it was handed is no longer accepted.

    """

    nonce: bytes
    response_type_oid: str | None = None
    resp_info: bytes | None = None
    expiry: int | None = None

    @property
    def requires_freshness(self) -> bool:
        """Return whether the RA issued a nonce this Evidence must be bound to."""
        return bool(self.nonce)

    def hpke_recipient_key(self) -> ec.EllipticCurvePublicKey | None:
        """Return the verifier's HPKE recipient key, when this exchange published one.

        ``None`` — never an exception — when the response carries a different syntax:
        an attester that supports several profiles asks each accessor in turn, and a
        profile it was not provisioned for is simply not this exchange.

        :raises ValueError: the response *is* an HPKE exchange but its key is unusable.
        """
        if self.resp_info is None or self.response_type_oid != _hpke_params_oid():
            return None
        return hpke_key_from_spki_der(self.resp_info)


def parse_verifier_info(response: NonceResponse | bytes | bytearray) -> VerifierInfo:
    """Read a ``NonceResponse`` (decoded or DER) into a :class:`VerifierInfo`.

    :raises ValueError: the DER is not a well-formed ``NonceResponse``.
    """
    if isinstance(response, (bytes, bytearray)):
        response = try_decode_pyasn1(bytes(response), NonceResponse)

    info = VerifierInfo(
        nonce=bytes(response["nonce"]),
        response_type_oid=nonce_response_type_oid(response),
        resp_info=nonce_response_info(response),
        expiry=int(response["expiry"]) if response["expiry"].isValue else None,
    )
    logger.debug(
        "attester: verifier info type=%s respInfo=%dB nonce=%dB expiry=%s",
        info.response_type_oid,
        len(info.resp_info or b""),
        len(info.nonce),
        info.expiry,
    )
    return info


def _hpke_params_oid() -> str:
    """Resolve the HPKE evidence-parameters response OID at call time.

    Resolved per call rather than at import: the OID is deployment-configurable, and a
    module-level constant would freeze whatever value happened to be set when
    :mod:`libattest.attester` was first imported.
    """
    return get_nonce_response_oid_for_name("jose-hpke-evidence-params")


__all__ = [
    "VerifierInfo",
    "parse_verifier_info",
]
