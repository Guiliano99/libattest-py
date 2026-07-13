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

    # Validate each supplied chain link leaf -> intermediate.
    for cert, issuer in zip(chain, chain[1:]):
        if cert.issuer != issuer.subject:
            raise ValueError("certificate issuer does not match next chain subject")
        _verify_cert_signature(cert, issuer)

    # Terminate the supplied chain at one configured trust root.
    last = chain[-1]
    for root in roots:
        if last.issuer != root.subject:
            continue
        _verify_cert_signature(last, root)
        # Trust anchor should be self-consistent when used as a root.
        if root.issuer == root.subject:
            _verify_cert_signature(root, root)
        return

    raise InvalidSignature("certificate chain does not terminate at a trusted root")


__all__ = ["validate_ek_chain"]
