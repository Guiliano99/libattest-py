# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""In-process verifier for NXP SE05x attested reads (``se05x-attest``).

The Evidence is a DER ``Se05xAttestEvidence``: the recorded attested-read command
and the SE's response body (:mod:`libattest.formats.se05x`). The verifier trusts
nothing the Attester carries beside the signed bytes: the freshness is ``TAG_7``
of the signed command, compared with the RA nonce, and the attested key is
``TAG_1`` of the signed response, compared with the to-be-certified key.

On success it issues an EAR (submodule ``SE05X``, ``ear.status`` ``affirming``) with
one AR4SI claim, ``instance-identity`` = 2 (draft-ietf-rats-ar4si-10 §2.3.4): "The
Attesting Environment is recognized, and the associated instance of the Attester is
not known to be compromised." Recognized means: it holds the key of an attestation
certificate issued under the configured roots, and it signed the fresh RA nonce.
Every other claim is omitted, which means "no claim", not "good": ``hardware`` = 2
needs NXP's attestation CA as the root plus a revocation input, neither of which
exists here. Key provenance (origin INTERNAL, type, size, object id) is a gate for
``affirming``, not a claim. On any failure it returns ``contraindicated`` and no EAR.

Caveats: with the demo root the claim means "issued by the demo root", which the
required ``policy_id`` names; the roots must certify only SE05x attestation keys,
since any end-entity signing key under them can sign Evidence; a simulator started with ``SE050_SIM_ATTEST_SEED`` has
a derivable attestation key, so the claim is false for it; the chip id is signed but
not bound to the certificate; the EAR carries no Identity Evidence (AR4SI §2.2), the
one-shot RA nonce ties it to the exchange instead.
"""

from __future__ import annotations

import hmac
import logging
from typing import TYPE_CHECKING, ClassVar

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE, base_media_type
from libattest.formats.se05x import apdu
from libattest.formats.se05x.structures import decode_se05x_attest_evidence
from libattest.types import VerifyResult
from libattest.verifier.ear import build_ear_jwt
from libattest.verifier.trust import validate_ek_chain

if TYPE_CHECKING:
    from libattest.ra.ports import AppraisalRequest

logger = logging.getLogger(__name__)

#: ``ear.verifier-id.developer`` of issued EARs unless configured otherwise.
DEFAULT_VERIFIER_DEVELOPER = "libattest-se05x-verifier"
#: The EAR ``submods`` key.
SCHEME_NAME = "SE05X"

_P256_POINT_LEN = 65  # 04 || X(32) || Y(32)


class Se05xAttestVerifier:
    """Appraise SE05x attested reads of a P-256 key pair and issue an AR4SI EAR.

    Implements the RA's :class:`~libattest.ra.ports.EvidenceVerifier` port natively,
    because it needs the request's endorsements (the attestation certificate chain)
    and subject key, which the older ``verify_token`` interface cannot carry.

    Parameters
    ----------
    roots:
        Trusted attestation roots; the Evidence's certificate chain (leaf first, from
        ``AppraisalRequest.endorsements``) must end at one of them. They must be CAs
        that certify only SE05x attestation keys (for NXP: pin the attestation-issuing
        CA): any other signing key certified under them can forge Evidence, and the
        ``TAG_5`` key-id check cannot tell, because the leaf certificate fixes the signer.
    policy_id:
        ``ear.appraisal-policy-id``, naming the trust-anchor class, e.g.
        ``policy:SE05X/demo-sim-root``. Required, so a demo-rooted appraisal can
        never look like an NXP-rooted one.
    ear_signing_key:
        P-256 key that signs issued EARs (publish :meth:`ear_verification_pem`);
        a fresh one is generated when omitted.
    verifier_developer:
        ``ear.verifier-id.developer`` stamped into issued EARs.

    Raises
    ------
    ValueError
        If *roots* or *policy_id* is empty.

    """

    #: The Evidence media type; an RA profile reads it from the verifier.
    media_type: ClassVar[str] = SE05X_ATTESTATION_MEDIA_TYPE
    #: Media types :meth:`appraise` accepts (not a ClassVar: the RA port declares it per instance).
    accepts: frozenset[str] = frozenset({SE05X_ATTESTATION_MEDIA_TYPE})

    def __init__(
        self,
        *,
        roots: list[x509.Certificate],
        policy_id: str,
        ear_signing_key: ec.EllipticCurvePrivateKey | None = None,
        verifier_developer: str = DEFAULT_VERIFIER_DEVELOPER,
    ) -> None:
        """Store the trust roots, the appraisal policy id and the EAR signing key."""
        if not roots:
            raise ValueError("Se05xAttestVerifier needs at least one trusted attestation root")
        if not policy_id:
            raise ValueError("Se05xAttestVerifier needs a policy_id naming its trust-anchor class")
        self._roots = list(roots)
        self._policy_id = policy_id
        self._ear_signing_key = ear_signing_key or ec.generate_private_key(ec.SECP256R1())
        self._verifier_developer = verifier_developer

    @property
    def verifier_id(self) -> str:
        """Return the ``ear.verifier-id.developer`` this instance stamps into its EARs."""
        return self._verifier_developer

    def ear_verification_pem(self) -> str:
        """Return the EAR-JWT signing public key (PEM), the RA's pinned EAR anchor."""
        return (
            self._ear_signing_key.public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode("ascii")
        )

    def appraise(self, request: AppraisalRequest) -> VerifyResult:
        """Appraise one SE05x statement; return an affirming EAR or ``contraindicated``.

        The affirming EAR echoes ``request.nonce`` and carries the trust vector
        ``{"instance-identity": 2}`` under the configured policy id.
        """
        reason = self._first_failure(request)
        if reason is not None:
            logger.warning("SE05x appraisal failed: %s", reason)
            return VerifyResult.contraindicated(reason)
        return VerifyResult.affirming(
            build_ear_jwt(
                signing_key=self._ear_signing_key,
                verifier_developer=self._verifier_developer,
                scheme_name=SCHEME_NAME,
                nonce=request.nonce,
                status="affirming",
                trust_vector={"instance-identity": 2},
                policy_id=self._policy_id,
            )
        )

    def _first_failure(self, request: AppraisalRequest) -> str | None:
        """Run the checks, cheapest first, and return the first failure's reason, or ``None``."""
        if base_media_type(request.media_type) not in self.accepts:
            return f"unsupported media type {request.media_type!r}; expected {self.media_type!r}"
        if len(request.nonce) != apdu.FRESHNESS_LEN:
            return (
                f"SE05x attestation needs a {apdu.FRESHNESS_LEN}-byte RA nonce, got {len(request.nonce)} bytes; "
                f"configure the RA with NonceStore(nonce_bytes={apdu.FRESHNESS_LEN})"
            )
        try:
            evidence = decode_se05x_attest_evidence(request.evidence)
        except ValueError as exc:
            return f"Evidence is not a DER Se05xAttestEvidence: {exc}"
        command_bytes = bytes(evidence["commandApdu"])
        try:
            command = apdu.parse_attested_read_command(command_bytes)
        except ValueError as exc:
            return f"command APDU rejected: {exc}"
        if command.attest_key_id != apdu.ATTEST_KEY_ID:
            return f"attestation key id {command.attest_key_id:#010x} is not {apdu.ATTEST_KEY_ID:#010x}"
        if command.algo != apdu.ALGO_ECDSA_SHA256:
            return f"attestation algorithm {command.algo:#04x} is not ECDSA with SHA-256 (0x21)"
        if not hmac.compare_digest(command.freshness, request.nonce):
            return "freshness TAG_7 of the signed command does not match the RA nonce"
        try:
            response = apdu.parse_attested_read_response(bytes(evidence["responseBody"]))
        except ValueError as exc:
            return f"response body rejected: {exc}"
        if response.value is None:
            return "response carries no TAG_1: the attested object's value was not returned"
        if len(response.value) != _P256_POINT_LEN or response.value[0] != 0x04:
            return "TAG_1 is not a 65-byte uncompressed P-256 point"
        try:
            subject_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), response.value)
        except ValueError:
            return "TAG_1 is not a point on P-256"
        try:
            attributes = apdu.parse_attributes(response.attributes)
        except ValueError as exc:
            return f"object attributes rejected: {exc}"
        if attributes.object_id != command.object_id:
            return f"attribute object id {attributes.object_id:#010x} is not the read object {command.object_id:#010x}"
        if attributes.type_code != apdu.TYPE_EC_KEY_PAIR_NIST_P256:
            return f"object type {attributes.type_code:#04x} is not a P-256 key pair (0x29)"
        if attributes.origin != apdu.ORIGIN_INTERNAL:
            return f"key origin {attributes.origin:#04x} is not INTERNAL (0x02): the key was not generated in the SE"
        if response.object_size != apdu.P256_KEY_SIZE:
            return f"object size {response.object_size:#06x} is not the P-256 size 0x0020"
        # The endorsements come from the Attester: any parse failure is a rejection, never a crash.
        try:
            chain = [x509.load_der_x509_certificate(der) for der in request.endorsements]
            validate_ek_chain(chain=chain, roots=self._roots)
            if not _is_end_entity_signer(chain[0]):
                return "attestation certificate is not an end-entity signing certificate"
            leaf_key = chain[0].public_key()
        except (ValueError, InvalidSignature, UnsupportedAlgorithm, x509.DuplicateExtension) as exc:
            return f"attestation certificate chain rejected: {str(exc) or type(exc).__name__}"
        if not isinstance(leaf_key, ec.EllipticCurvePublicKey) or not isinstance(leaf_key.curve, ec.SECP256R1):
            return "attestation certificate key is not a P-256 key"
        try:
            leaf_key.verify(response.signature, apdu.signed_message(command_bytes, response), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return "Evidence signature does not verify with the attestation certificate key"
        if request.subject_key is not None:
            # Compare keys, not bytes: RFC 5480 allows other encodings of the same key (a compressed point).
            try:
                given = serialization.load_der_public_key(request.subject_key)
            except (ValueError, UnsupportedAlgorithm):
                return "subject key is not a DER SubjectPublicKeyInfo"
            if given != subject_key:
                return "subject key does not match the attested key (TAG_1)"
        return None


def _is_end_entity_signer(cert: x509.Certificate) -> bool:
    """Return whether *cert* is not a CA and, when it has a keyUsage, allows ``digitalSignature``."""
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    except x509.ExtensionNotFound:
        pass
    try:
        return cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
    except x509.ExtensionNotFound:
        return True


__all__ = ["DEFAULT_VERIFIER_DEVELOPER", "SCHEME_NAME", "Se05xAttestVerifier"]
