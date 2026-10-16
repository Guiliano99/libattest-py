# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""X.509 trust helpers for verifier-side attestation appraisal.

The TPM platform/key-attestation verifiers split signature verification: the AK
**certificate chain** is validated here with ``cryptography`` (X.509), while the
attestation-**statement** signature is verified with the TPMT_SIGNATURE helpers.
"""

from __future__ import annotations

import datetime as _dt

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def _verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    issuer_key = issuer.public_key()
    hash_algorithm = cert.signature_hash_algorithm
    if hash_algorithm is None:
        raise ValueError("certificate signature has no hash algorithm")
    if isinstance(issuer_key, rsa.RSAPublicKey):
        issuer_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hash_algorithm,
        )
        return
    if isinstance(issuer_key, ec.EllipticCurvePublicKey):
        issuer_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(hash_algorithm),
        )
        return
    raise ValueError(f"unsupported issuer public key type: {type(issuer_key).__name__}")


def _is_ca(cert: x509.Certificate) -> bool:
    """Return whether *cert* asserts the CA bit in basicConstraints."""
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _check_issuer_capability(cert: x509.Certificate, *, cas_below: int) -> None:
    """Assert *cert* is permitted to issue certificates (RFC 5280 §4.2.1.9, §4.2.1.3).

    ``cas_below`` is the number of CA certificates that follow *cert* in the path,
    which ``pathLenConstraint`` bounds.  A missing ``basicConstraints`` on an issuer
    is fatal rather than permissive: without it nothing asserts the key may sign
    certificates at all, which is exactly the substitution this check exists to stop.
    ``keyUsage`` is optional, but when present it must permit ``keyCertSign``.
    """
    subject = cert.subject.rfc4514_string()
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise ValueError(f"issuer {subject!r} has no basicConstraints extension; it is not a CA") from None
    if not constraints.ca:
        raise ValueError(f"issuer {subject!r} is not a CA (basicConstraints CA=FALSE)")
    if constraints.path_length is not None and constraints.path_length < cas_below:
        raise ValueError(
            f"issuer {subject!r} has pathLenConstraint={constraints.path_length} "
            f"but {cas_below} CA certificate(s) follow it in the path"
        )

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return  # keyUsage is optional; basicConstraints already gates issuance.
    if not key_usage.key_cert_sign:
        raise ValueError(f"issuer {subject!r} keyUsage does not permit keyCertSign")


def _check_time_validity(cert: x509.Certificate, now: _dt.datetime) -> None:
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if now < not_before or now > not_after:
        raise ValueError(
            f"certificate not valid at {now.isoformat()} (valid {not_before.isoformat()}..{not_after.isoformat()})"
        )


def validate_ek_chain(
    *,
    chain: list[x509.Certificate],
    roots: list[x509.Certificate],
) -> None:
    """Validate an AK/EK certificate chain against trusted roots.

    ``chain`` is ordered leaf-first (AK cert first, optional intermediates
    after).  ``roots`` contains trusted CA certificates.  The function raises
    :class:`cryptography.exceptions.InvalidSignature` for signature failures and
    :class:`ValueError` for malformed, expired, or untrusted chains.  It returns
    ``None`` on success.
    """
    if not chain:
        raise ValueError("empty certificate chain")
    if not roots:
        raise ValueError("empty trust-root set")

    now = _dt.datetime.now(_dt.timezone.utc)
    for cert in [*chain, *roots]:
        _check_time_validity(cert, now)

    # Validate each supplied chain link leaf -> intermediate.  Every issuer must be
    # entitled to issue, not merely hold the key that signed the link below it.
    for index, (cert, issuer) in enumerate(zip(chain, chain[1:])):
        if cert.issuer != issuer.subject:
            raise ValueError("certificate issuer does not match next chain subject")
        _check_issuer_capability(issuer, cas_below=sum(1 for below in chain[: index + 1] if _is_ca(below)))
        _verify_cert_signature(cert, issuer)

    # Terminate the supplied chain at one configured trust root.
    last = chain[-1]
    cas_in_chain = sum(1 for cert in chain if _is_ca(cert))
    for root in roots:
        if last.issuer != root.subject:
            continue
        _check_issuer_capability(root, cas_below=cas_in_chain)
        _verify_cert_signature(last, root)
        # Trust anchor should be self-consistent when used as a root.
        if root.issuer == root.subject:
            _verify_cert_signature(root, root)
        return

    raise InvalidSignature("certificate chain does not terminate at a trusted root")


__all__ = ["validate_ek_chain"]
