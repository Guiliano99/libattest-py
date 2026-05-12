# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""ASN.1 structures for CSR attestation bundles.

This module intentionally matches the structure shape currently consumed by
the MockCA prototype. The names mirror the existing `resources.remote_att_utils`
modules so MockCA can later re-export these classes with minimal churn.
"""

import base64
import re
from collections.abc import Iterable
from pathlib import Path
from typing import TypeAlias

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder
from pyasn1.type import constraint, namedtype, tag, univ
from pyasn1_alt_modules import rfc9480

id_aa_attestation = univ.ObjectIdentifier("1.2.840.113549.1.9.16.2.59")


class OtherCertificateFormat(univ.Sequence):
    """Non-X.509 certificate format wrapper."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("otherCertFormat", univ.ObjectIdentifier()),
        namedtype.NamedType("otherCert", univ.Any()),
    )


class LimitedCertChoices(univ.Choice):
    """Certificate choices limited to X.509 certificates and other formats."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("certificate", rfc9480.CMPCertificate()),
        namedtype.NamedType(
            "other",
            OtherCertificateFormat().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext,
                    tag.tagFormatConstructed,
                    3,
                )
            ),
        ),
    )


class AttestationStatement(univ.Sequence):
    """One attestation statement inside an attestation bundle."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("stmt", univ.Any()),
    )


class AttestationSequence(univ.SequenceOf):
    """SEQUENCE SIZE (1..MAX) OF AttestationStatement."""

    componentType = AttestationStatement()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


class AttestCertSequence(univ.SequenceOf):
    """SEQUENCE SIZE (1..MAX) OF LimitedCertChoices."""

    componentType = LimitedCertChoices()
    subtypeSpec = constraint.ValueSizeConstraint(1, float("inf"))


class AttestationBundle(univ.Sequence):
    """Container for attestation statements and optional validation certs."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestations", AttestationSequence()),
        namedtype.OptionalNamedType("certs", AttestCertSequence()),
    )


StatementPayload: TypeAlias = univ.Sequence | univ.OctetString | univ.Any | bytes
CertificateInput: TypeAlias = rfc9480.CMPCertificate | LimitedCertChoices | OtherCertificateFormat


def _prepare_stmt(stmt: StatementPayload) -> univ.Sequence | univ.OctetString | univ.Any:
    """Coerce raw DER bytes into `Any` for the open-type statement field."""

    if isinstance(stmt, bytes):
        return univ.Any(stmt)
    return stmt


def prepare_attestation_statement(
    stmt_id: univ.ObjectIdentifier,
    stmt: StatementPayload,
) -> AttestationStatement:
    """Build an `AttestationStatement` from an OID and open-type payload."""

    value = AttestationStatement()
    value["type"] = stmt_id
    value["stmt"] = _prepare_stmt(stmt)
    return value


def prepare_opaque_attestation_statement(
    stmt_id: univ.ObjectIdentifier,
    payload: bytes,
) -> AttestationStatement:
    """Build a statement for a non-ASN.1 payload such as a JWT.

    The payload is DER-wrapped as an OCTET STRING because ``stmt`` is an ASN.1
    open type.  Use :func:`prepare_asn1_attestation_statement` when the
    evidence is already a DER-encoded ASN.1 structure.
    """

    wrapped_payload = encoder.encode(univ.OctetString(payload))
    return prepare_attestation_statement(stmt_id, wrapped_payload)


def prepare_asn1_attestation_statement(
    stmt_id: univ.ObjectIdentifier,
    der_payload: bytes,
) -> AttestationStatement:
    """Build a statement for evidence that is already a DER-encoded ASN.1 value.

    Unlike :func:`prepare_opaque_attestation_statement`, the DER bytes are
    embedded directly as an open-type ``Any`` without an additional OCTET STRING
    wrapper.  Use this when the evidence is a SEQUENCE such as
    ``TcgAttestCertify``.
    """

    return prepare_attestation_statement(stmt_id, der_payload)


def _as_limited_cert_choice(cert: CertificateInput) -> LimitedCertChoices:
    """Convert supported certificate inputs into `LimitedCertChoices`."""

    if isinstance(cert, LimitedCertChoices):
        return cert
    if isinstance(cert, rfc9480.CMPCertificate):
        return LimitedCertChoices().setComponentByName("certificate", cert)
    if isinstance(cert, OtherCertificateFormat):
        return LimitedCertChoices().setComponentByName("other", cert)
    raise TypeError(f"Unexpected certificate input type: {type(cert).__name__}")


def prepare_attestation_bundle(
    attestations: Iterable[AttestationStatement],
    certs: Iterable[CertificateInput] | None = None,
) -> AttestationBundle:
    """Build an `AttestationBundle` from statements and optional certs."""

    value = AttestationBundle()
    value["attestations"].extend(attestations)
    if certs is not None:
        value["certs"].extend(_as_limited_cert_choice(cert) for cert in certs)
    return value


def prepare_multi_statement_bundle(
    results: "Iterable[object]",
    certs: Iterable[CertificateInput] | None = None,
) -> AttestationBundle:
    """Build an `AttestationBundle` from multiple :class:`AttestResult`-like values.

    For each result, the OID is taken from ``.oid`` and the evidence from
    ``.evidence_bytes()``.  Statements are wrapped according to the result's
    ``is_asn1_evidence`` flag (when present):

    * ``is_asn1_evidence=True``  → :func:`prepare_asn1_attestation_statement`
    * ``is_asn1_evidence=False`` → :func:`prepare_opaque_attestation_statement`

    Results without that flag default to opaque (OCTET STRING) wrapping —
    matching the existing single-result helper.

    Parameters
    ----------
    results:
        Iterable of ``AttestResult`` instances (or objects with the same
        ``oid`` / ``evidence_bytes()`` / ``is_asn1_evidence`` shape).
    certs:
        Optional certificate chain shared by all statements (e.g. AK chain).
    """
    statements: list[AttestationStatement] = []
    for result in results:
        oid = univ.ObjectIdentifier(result.oid)
        evidence = result.evidence_bytes()
        if getattr(result, "is_asn1_evidence", False):
            statements.append(prepare_asn1_attestation_statement(oid, evidence))
        else:
            statements.append(prepare_opaque_attestation_statement(oid, evidence))
    return prepare_attestation_bundle(statements, certs=certs)


_PEM_CERT_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----",
    re.DOTALL,
)


def pem_chain_to_cmp_certs(pem: str | Path) -> list[rfc9480.CMPCertificate]:
    """Parse a PEM certificate chain into a list of :class:`rfc9480.CMPCertificate`.

    Parameters
    ----------
    pem:
        PEM text or a :class:`~pathlib.Path` pointing to a PEM file.

    Returns
    -------
    list[rfc9480.CMPCertificate]
        One entry per ``BEGIN CERTIFICATE`` block found in *pem*.

    Raises
    ------
    ValueError
        If *pem* contains no certificate blocks.
    pyasn1.error.SubstrateUnderrunError
        If a DER block cannot be decoded as an X.509 certificate.
    """
    pem_text = Path(pem).read_text() if isinstance(pem, Path) else pem
    matches = _PEM_CERT_PATTERN.findall(pem_text)
    if not matches:
        raise ValueError("No PEM certificate blocks found")
    certs = []
    for b64 in matches:
        der = base64.b64decode(b64)
        cert, _ = der_decoder.decode(der, asn1Spec=rfc9480.CMPCertificate())
        certs.append(cert)
    return certs


def get_attestation_bundle_certs(attestation_bundle: AttestationBundle) -> list[rfc9480.CMPCertificate]:
    """Return X.509 certificates from an attestation bundle."""

    if not attestation_bundle["certs"].isValue:
        return []

    certs = []
    for entry in attestation_bundle["certs"]:
        if entry.getName() != "certificate":
            raise NotImplementedError("Only X.509 certificate entries are supported.")
        certs.append(entry["certificate"])
    return certs
