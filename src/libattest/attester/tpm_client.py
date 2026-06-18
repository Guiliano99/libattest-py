# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Device-side TPM 2.0 access layer built on ``tpm2-pytss`` (ESAPI).

``TpmClient`` is a thin, attestation-focused wrapper over the tpm2-pytss ESAPI
(the TCG Enhanced System API).  It speaks to a TPM reached through a TCTI; in
the bundled ``docker/tpm-demo`` setup that TPM is the IBM Software TPM 2.0
simulator (``tpm_server``), reached over the ``mssim`` TCTI (command port 2321,
platform port 2322).

This module owns only the *TPM primitives* — the operations that physically
touch the TPM:

* connect / startup / teardown,
* provision an Endorsement Key (EK) and an Attestation Key (AK),
* run ``TPM2_Quote`` and parse the returned C structures into plain Python
  (``QuoteResult.to_evidence()`` yields a
  :class:`libattest.formats.tpm.tpms_attest.TpmQuoteSignatureEvidence`),
* the CA and device halves of credential activation
  (``TPM2_MakeCredential`` / ``TPM2_ActivateCredential``) — the operations that
  recover the verifier ``seed`` used by the v5 ``KeyAttestPoP`` flow.

This client performs real ESAPI calls and therefore requires the mandatory
``tpm2-pytss`` package (and a built ``tpm2-tss``), which is imported at module
load time.

All section numbers below refer to the TPM 2.0 Library Specification v1.85:

  TPM2_Quote command / response ......... Part 3, Sec. 18.4, Tables 101/102
  signing-scheme selection rules ........ Part 3, Sec. 18.1
  TPMS_ATTEST (the signed statement) .... Part 2, Sec. 10.11.12, Table 154
  TPMS_QUOTE_INFO (the quote payload) ... Part 2, Sec. 10.11.4,  Table 146
  TPM2B_ATTEST (size-prefixed wrapper) .. Part 2, Sec. 10.11.13, Table 155
  credential protection ................. Part 1, Sec. 24
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union

from tpm2_pytss import (
    ESAPI,
    ESYS_TR,
    TPM2_ALG,
    TPM2_RC,
    TPM2_SE,
    TPM2_SU,
    TPM2B_ATTEST,
    TPM2B_ENCRYPTED_SECRET,
    TPM2B_ID_OBJECT,
    TPM2B_NAME,
    TPM2B_PUBLIC,
    TPMA_OBJECT,
    TPMT_PUBLIC,
    TPMT_SIGNATURE,
    TSS2_Exception,
)

# These helpers live in the ``utils`` submodule and are NOT re-exported at the
# package top level, so they have to be imported explicitly.
from tpm2_pytss.utils import (
    NVReadEK,
    create_ek_template,
    make_credential,
)

from libattest.formats.tpm.tpms_attest import (
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TpmQuoteSignatureEvidence,
    parse_tpms_attest,
    pcr_mask_to_indices,
)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
# ``TPM_GENERATED_VALUE`` and ``TPM_ST_ATTEST_QUOTE`` are imported from
# ``libattest.formats.tpm.tpms_attest`` (the single source of truth) so the
# attester and verifier never define them independently.

# Friendly hash name -> TPM algorithm id (Part 2 / TCG Algorithm Registry).
_HASHES = {
    "sha1": TPM2_ALG.SHA1,
    "sha256": TPM2_ALG.SHA256,
    "sha384": TPM2_ALG.SHA384,
    "sha512": TPM2_ALG.SHA512,
}
_ALG_NAMES = {int(v): k for k, v in _HASHES.items()}


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #
def _ak_template(alg_family: str, hash_alg: str) -> TPM2B_PUBLIC:
    """Build the public template for an Attestation Key.

    An AK is a *restricted signing* key (``RESTRICTED | SIGN_ENCRYPT``).
    ``restricted`` is the property that makes the TPM enforce the
    ``TPM_GENERATED_VALUE`` rule, so the AK can only sign digests the TPM itself
    produced — never attacker-chosen bytes shaped like an attestation.  The
    signing scheme (and therefore the hash used by ``TPM2_Quote``) is fixed here
    at creation time.

    The tpm2-tools-style algorithm string has three colon-separated parts,
    ``type:scheme:symmetric``.  The trailing ``:null`` forces the symmetric
    field to ``TPM_ALG_NULL`` — mandatory for a sign-only key (otherwise
    tpm2-pytss would default a restricted key to AES, which the TPM rejects for
    a signing key).
    """
    if hash_alg not in _HASHES:
        raise ValueError(f"unsupported hash {hash_alg!r}; pick one of {list(_HASHES)}")

    attrs = (
        TPMA_OBJECT.FIXEDTPM  # key never leaves this TPM
        | TPMA_OBJECT.FIXEDPARENT  # cannot be re-parented
        | TPMA_OBJECT.SENSITIVEDATAORIGIN  # TPM generated the private part
        | TPMA_OBJECT.USERWITHAUTH  # USER role authorized by the auth value
        | TPMA_OBJECT.RESTRICTED  # restricted ...
        | TPMA_OBJECT.SIGN_ENCRYPT  # ... signing key  ==  an Attestation Key
    )

    if alg_family == "rsa":
        spec = f"rsa2048:rsassa-{hash_alg}:null"
    elif alg_family == "ecc":
        spec = f"ecc256:ecdsa-{hash_alg}:null"
    else:
        raise ValueError("alg_family must be 'rsa' or 'ecc'")

    public_area = TPMT_PUBLIC.parse(
        alg=spec,
        objectAttributes=attrs,
        nameAlg=_HASHES[hash_alg],
    )
    return TPM2B_PUBLIC(publicArea=public_area)


# --------------------------------------------------------------------------- #
# Parsed quote result
# --------------------------------------------------------------------------- #
@dataclass
class QuoteResult:
    """A ``TPM2_Quote`` response unpacked into plain Python.

    ``quoted`` and ``signature`` are the raw structures straight off the TPM;
    everything else is decoded from them.  Call :meth:`to_evidence` to hand the
    signed quote to the verifier as a
    :class:`~libattest.formats.tpm.tpms_attest.TpmQuoteSignatureEvidence`.
    """

    quoted: TPM2B_ATTEST  # raw, size-prefixed wrapper (Table 155)
    signature: TPMT_SIGNATURE  # raw signature structure

    magic: int  # TPMS_ATTEST.magic
    attest_type: int  # TPMS_ATTEST.type  (0x8018 == ATTEST_QUOTE)
    nonce: bytes  # TPMS_ATTEST.extraData  ==  the verifier qualifyingData
    qualified_signer: bytes  # TPMS_ATTEST.qualifiedSigner (AK Qualified Name)

    clock: int  # TPMS_CLOCK_INFO.clock
    reset_count: int  # TPMS_CLOCK_INFO.resetCount
    restart_count: int  # TPMS_CLOCK_INFO.restartCount
    safe: bool  # TPMS_CLOCK_INFO.safe
    firmware_version: int  # TPMS_ATTEST.firmwareVersion

    pcr_digest: bytes  # TPMS_QUOTE_INFO.pcrDigest
    pcr_selection: str  # human form of TPMS_QUOTE_INFO.pcrSelect

    sig_alg: int  # TPMT_SIGNATURE.sigAlg
    sig_hash: int  # hash algorithm inside the signature
    sig_value: bytes  # raw signature bytes (RSA) or r||s (ECC)

    @property
    def is_tpm_generated(self) -> bool:
        """True iff the statement begins with ``TPM_GENERATED_VALUE``."""
        return self.magic == TPM_GENERATED_VALUE

    @property
    def is_quote(self) -> bool:
        """True iff the statement is a quote (``TPM_ST_ATTEST_QUOTE``)."""
        return self.attest_type == TPM_ST_ATTEST_QUOTE

    @property
    def attestation_bytes(self) -> bytes:
        """The exact octets that were signed: the marshalled ``TPMS_ATTEST``.

        For a ``TPM2B_ATTEST``, ``bytes(...)`` returns the *buffer contents*
        only (the size field is excluded), which is precisely
        ``attestationData`` — the signed portion per Part 2, Table 155.
        """
        return bytes(self.quoted)

    def to_evidence(self, ak_public_key: bytes) -> TpmQuoteSignatureEvidence:
        """Build verifier-ready evidence from this quote and the AK public key.

        ``ak_public_key`` is the AK SubjectPublicKeyInfo (PEM/DER) or X.509 AK
        certificate the verifier loads via ``cryptography`` to check the
        signature.  This replaces hand-copying the four signed-quote fields into
        a :class:`TpmQuoteSignatureEvidence` at every call site.
        """
        return TpmQuoteSignatureEvidence(
            attestation=self.attestation_bytes,
            signature=self.sig_value,
            signature_algorithm=self.sig_alg,
            signature_hash=self.sig_hash,
            ak_public_key=ak_public_key,
        )

    def summary(self) -> str:
        """Return a human-readable multi-line dump of the parsed quote."""
        return (
            f"magic           = {self.magic:#010x} "
            f"({'TPM-generated' if self.is_tpm_generated else 'NOT TPM-generated'})\n"
            f"type            = {self.attest_type:#06x} "
            f"({'ATTEST_QUOTE' if self.is_quote else 'other'})\n"
            f"nonce/extraData = {self.nonce.hex()}\n"
            f"qualifiedSigner = {self.qualified_signer.hex()}\n"
            f"clock           = {self.clock} ms, "
            f"reset={self.reset_count}, restart={self.restart_count}, safe={self.safe}\n"
            f"firmwareVersion = {self.firmware_version:#018x}\n"
            f"pcrSelect       = {self.pcr_selection}\n"
            f"pcrDigest       = {self.pcr_digest.hex()}\n"
            f"sigAlg          = {self.sig_alg:#06x}, sigHash = {self.sig_hash:#06x}\n"
            f"signature       = {self.sig_value.hex()}"
        )

    def to_dict(self) -> dict:
        """Return the parsed quote as JSON-serialisable values.

        Integers that read naturally in hex (magic, type, algorithm ids,
        firmware version) are rendered as hex strings; byte fields are rendered
        as hex.  ``attestation_bytes`` are the exact signed octets, so a
        verifier can re-check the signature straight from this dict.
        """
        return {
            "magic": f"{self.magic:#010x}",
            "is_tpm_generated": self.is_tpm_generated,
            "type": f"{self.attest_type:#06x}",
            "is_quote": self.is_quote,
            "nonce_extra_data": self.nonce.hex(),
            "qualified_signer": self.qualified_signer.hex(),
            "clock": self.clock,
            "reset_count": self.reset_count,
            "restart_count": self.restart_count,
            "safe": self.safe,
            "firmware_version": f"{self.firmware_version:#018x}",
            "pcr_select": self.pcr_selection,
            "pcr_digest": self.pcr_digest.hex(),
            "sig_alg": f"{self.sig_alg:#06x}",
            "sig_hash": f"{self.sig_hash:#06x}",
            "signature": self.sig_value.hex(),
            "attestation_bytes": self.attestation_bytes.hex(),
        }


def _selections_to_str(pcr_selections: list[dict]) -> str:
    """Render parsed ``pcr_selections`` as e.g. ``'sha256:0,1,2,3'``.

    Takes the ``[{"hash_alg", "pcr_mask"}, ...]`` list produced by the shared
    :func:`~libattest.formats.tpm.tpms_attest.parse_tpms_attest`, reusing
    :func:`~libattest.formats.tpm.tpms_attest.pcr_mask_to_indices` for the
    bitmask walk.
    """
    parts = []
    for sel in pcr_selections:
        bank = _ALG_NAMES.get(sel["hash_alg"], hex(sel["hash_alg"]))
        indices = pcr_mask_to_indices(sel["pcr_mask"])
        parts.append(f"{bank}:{','.join(str(p) for p in indices)}")
    return " + ".join(parts)


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #
class TpmClient:
    """Thin attestation client over the tpm2-pytss ESAPI.

    Typical use::

        from libattest.attester.tpm_client import TpmClient

        with TpmClient(tcti="mssim:host=tpmsim,port=2321") as tpm:
            tpm.provision_ek()
            tpm.provision_ak(hash_alg="sha256")
            qr = tpm.quote(nonce=verifier_nonce, pcr_selection="sha256:0,1,2,3,4")
            print(qr.summary())
    """

    def __init__(
        self,
        tcti: str = "mssim:host=127.0.0.1,port=2321",
        ak_family: str = "rsa",
        hash_alg: str = "sha256",
        ek_type: str = "EK-RSA2048",
    ) -> None:
        """Store connection/key parameters; :meth:`connect` opens the TPM context."""
        self._tcti = tcti
        self._ak_family = ak_family
        self._hash_alg = hash_alg
        self._ek_type = ek_type

        self._ectx: Optional[ESAPI] = None
        self.ek_handle: Optional[ESYS_TR] = None
        self.ek_public: Optional[TPM2B_PUBLIC] = None
        self.ek_certificate: Optional[bytes] = None  # DER bytes, or None on a bare TPM
        self.ak_handle: Optional[ESYS_TR] = None
        self.ak_public: Optional[TPM2B_PUBLIC] = None
        self.ak_name: Optional[TPM2B_NAME] = None

    # -- lifecycle --------------------------------------------------------- #
    def __enter__(self) -> "TpmClient":
        """Open the ESAPI context on entry."""
        return self.connect()

    def __exit__(self, *exc) -> None:
        """Flush handles and close the ESAPI context on exit."""
        self.close()

    def connect(self) -> "TpmClient":
        """Open the ESAPI context and run ``TPM2_Startup(CLEAR)``.

        Passing the TCTI as a string makes ESAPI load it through TCTILdr, i.e.
        the same ``name:conf`` syntax the tpm2-tools use (``mssim:...``,
        ``swtpm:...``, ``device:/dev/tpmrm0``).
        """
        self._ectx = ESAPI(self._tcti)
        try:
            self._ectx.startup(TPM2_SU.CLEAR)
        except TSS2_Exception as exc:
            # TPM_RC_INITIALIZE means startup already ran; anything else is real.
            if exc.rc != TPM2_RC.INITIALIZE:
                raise
        return self

    def close(self) -> None:
        """Flush the EK/AK handles and close the ESAPI context (idempotent)."""
        if self._ectx is None:
            return
        for handle in (self.ak_handle, self.ek_handle):
            if handle is not None:
                try:
                    self._ectx.flush_context(handle)
                except TSS2_Exception:
                    pass
        self._ectx.close()
        self._ectx = None

    @property
    def ectx(self) -> ESAPI:
        """Return the live ESAPI context, or raise if not connected."""
        if self._ectx is None:
            raise RuntimeError("not connected; call connect() or use as a context manager")
        return self._ectx

    # -- provisioning ------------------------------------------------------ #
    def provision_ek(self) -> Tuple[TPM2B_PUBLIC, Optional[bytes]]:
        """Create the EK as a primary in the Endorsement hierarchy.

        ``create_ek_template`` reproduces the TCG-standard EK template and also
        tries to read the EK certificate from its well-known NV index
        (``0x01C00002`` for RSA-2048, ``0x01C0000A`` for ECC-P256).  A freshly
        manufactured simulator has no EK certificate provisioned there, so
        ``ek_certificate`` will normally be ``None`` — which is why key
        attestation relies on credential activation rather than an EK-cert
        chain here.
        """
        cert, template = create_ek_template(self._ek_type, NVReadEK(self.ectx))
        handle, public, _, _, _ = self.ectx.create_primary(
            in_sensitive=None,
            in_public=template,
            primary_handle=ESYS_TR.ENDORSEMENT,
        )
        self.ek_handle, self.ek_public, self.ek_certificate = handle, public, cert
        return public, cert

    def provision_ak(
        self,
        ak_family: Optional[str] = None,
        hash_alg: Optional[str] = None,
    ) -> Tuple[TPM2B_PUBLIC, TPM2B_NAME]:
        """Create the AK (restricted signing key) as a primary in the EH.

        The ``hash_alg`` chosen here becomes the AK's signing-scheme hash, which
        is the hash ``TPM2_Quote`` uses for both the PCR digest and the
        signature.
        """
        family = ak_family or self._ak_family
        chosen_hash = hash_alg or self._hash_alg
        template = _ak_template(family, chosen_hash)
        handle, public, _, _, _ = self.ectx.create_primary(
            in_sensitive=None,
            in_public=template,
            primary_handle=ESYS_TR.ENDORSEMENT,
        )
        self.ak_handle = handle
        self.ak_public = public
        self.ak_name = public.get_name()  # nameAlg || H_nameAlg(publicArea)
        self._hash_alg = chosen_hash
        return public, self.ak_name

    # -- the statement ----------------------------------------------------- #
    def quote(
        self,
        nonce: Union[bytes, str],
        pcr_selection: str = "sha256:0,1,2,3,4",
    ) -> QuoteResult:
        """Run ``TPM2_Quote`` and return the parsed result.

        Parameters
        ----------
        nonce:
            The verifier's qualifyingData.  It is copied verbatim into
            ``TPMS_ATTEST.extraData`` and covered by the signature, which is
            what makes the statement fresh / non-replayable.
        pcr_selection:
            tpm2-tools-style ``'bank:idx,idx,...'``.  The *bank* name (e.g.
            ``sha256``) selects which PCR bank is read; this is independent of
            the AK's signing hash.

        Notes
        -----
        ``in_scheme`` is left at ``TPM_ALG_NULL``: the AK is a restricted
        signing key, so per Part 3 Sec. 18.1 its scheme cannot be overridden
        and the TPM uses the AK's own scheme.  To attest with a different hash,
        provision a new AK with that hash.

        """
        if self.ak_handle is None:
            raise RuntimeError("no AK; call provision_ak() first")
        if isinstance(nonce, str):
            nonce = nonce.encode()

        quoted, signature = self.ectx.quote(
            self.ak_handle,  # sign_handle
            pcr_selection,  # pcr_select (str -> TPML_PCR_SELECTION)
            bytes(nonce),  # qualifying_data (the nonce)
        )
        return self.parse_quote(quoted, signature)

    @staticmethod
    def parse_quote(quoted: TPM2B_ATTEST, signature: TPMT_SIGNATURE) -> QuoteResult:
        """Decode a ``(TPM2B_ATTEST, TPMT_SIGNATURE)`` pair into a QuoteResult.

        The ``TPMS_ATTEST`` fields come from the shared
        :func:`~libattest.formats.tpm.tpms_attest.parse_tpms_attest` — one
        parser for the whole package — so only the signature decode below is
        attester-specific.
        """
        parsed = parse_tpms_attest(bytes(quoted))

        sig_alg = int(signature.sigAlg)
        if sig_alg == int(TPM2_ALG.RSASSA):
            sig_hash = int(signature.signature.rsassa.hash)
            sig_value = bytes(signature.signature.rsassa.sig)
        elif sig_alg == int(TPM2_ALG.RSAPSS):
            sig_hash = int(signature.signature.rsapss.hash)
            sig_value = bytes(signature.signature.rsapss.sig)
        elif sig_alg == int(TPM2_ALG.ECDSA):
            sig_hash = int(signature.signature.ecdsa.hash)
            r = bytes(signature.signature.ecdsa.signatureR)
            s = bytes(signature.signature.ecdsa.signatureS)
            sig_value = r + s  # raw concatenation; verifier re-encodes as needed
        else:
            sig_hash, sig_value = 0, b""

        return QuoteResult(
            quoted=quoted,
            signature=signature,
            magic=parsed.magic,
            attest_type=parsed.attest_type,
            nonce=parsed.nonce,
            qualified_signer=parsed.qualified_signer,
            clock=parsed.clock,
            reset_count=parsed.reset_count,
            restart_count=parsed.restart_count,
            safe=parsed.safe,
            firmware_version=parsed.firmware_version,
            pcr_digest=parsed.pcr_digest,
            pcr_selection=_selections_to_str(parsed.pcr_selections),
            sig_alg=sig_alg,
            sig_hash=sig_hash,
            sig_value=sig_value,
        )

    # -- credential activation (binds the AK to the EK) -------------------- #
    def make_credential_challenge(self, secret: bytes) -> Tuple[TPM2B_ID_OBJECT, TPM2B_ENCRYPTED_SECRET]:
        """CA side, no TPM required.

        Wraps ``secret`` so it can only be recovered by a TPM that owns both
        this EK (it decrypts the seed) and the AK whose Name is bound in.  This
        is the standard proof that the AK is co-resident with the EK, and the
        step a CA performs before issuing an AK certificate.  In the v5
        ``KeyAttestResp`` profile the verifier runs this (or an equivalent
        software MakeCredential) and the recovered plaintext *is* the ``seed``.
        """
        if self.ek_public is None or self.ak_name is None:
            raise RuntimeError("provision the EK and AK first")
        return make_credential(self.ek_public, secret, self.ak_name)

    def activate_credential(
        self,
        credential_blob: TPM2B_ID_OBJECT,
        encrypted_secret: TPM2B_ENCRYPTED_SECRET,
    ) -> bytes:
        """Device side.  Recovers the secret iff the AK and EK live in this TPM.

        The EK's authorization is a policy (``PolicySecret`` bound to the
        endorsement hierarchy), so the EK handle has to be authorized with a
        *policy* session rather than a password.  In the v5 ``KeyAttestResp``
        profile the recovered bytes are the verifier ``seed`` the requested key
        then signs into ``KeyAttestPoP``.
        """
        if self.ak_handle is None or self.ek_handle is None:
            raise RuntimeError("provision the EK and AK first")

        ek_session = self.ectx.start_auth_session(
            tpm_key=ESYS_TR.NONE,
            bind=ESYS_TR.NONE,
            session_type=TPM2_SE.POLICY,
            symmetric="aes128cfb",
            auth_hash=TPM2_ALG.SHA256,
        )
        try:
            # PolicySecret over the endorsement hierarchy with empty
            # nonceTPM / cpHashA / policyRef and no expiration -- the standard
            # way to satisfy the EK's auth policy. ESAPI.policy_secret takes
            # these three TPM2B_* arguments positionally (empty bytes -> empty
            # buffers); ESYS_TR.PASSWORD (session1 default) authorizes ENDORSEMENT.
            self.ectx.policy_secret(
                ESYS_TR.ENDORSEMENT,  # auth_handle: hierarchy whose secret gates the policy
                ek_session,  # policy_session being configured
                b"",  # nonce_tpm
                b"",  # cp_hash_a
                b"",  # policy_ref
                expiration=0,
            )
            recovered = self.ectx.activate_credential(
                activate_handle=self.ak_handle,  # AK provides the Name (ADMIN role)
                key_handle=self.ek_handle,  # EK decrypts the seed (USER role)
                credential_blob=credential_blob,
                secret=encrypted_secret,
                session1=ESYS_TR.PASSWORD,  # authorizes the AK
                session2=ek_session,  # authorizes the EK
            )
            return bytes(recovered)
        finally:
            self.ectx.flush_context(ek_session)

    # -- small helpers ----------------------------------------------------- #
    def ak_public_pem(self) -> bytes:
        """Return the AK public key as a SubjectPublicKeyInfo PEM."""
        if self.ak_public is None:
            raise RuntimeError("no AK")
        return self.ak_public.to_pem()

    def ak_public_der(self) -> bytes:
        """Return the AK public key as a SubjectPublicKeyInfo DER."""
        if self.ak_public is None:
            raise RuntimeError("no AK")
        return self.ak_public.to_der()

    def get_random(self, num_bytes: int = 32) -> bytes:
        """Return ``num_bytes`` from ``TPM2_GetRandom``.

        Useful for local testing only; a real freshness nonce must come from
        the verifier.
        """
        return bytes(self.ectx.get_random(num_bytes))


__all__ = [
    "TPM_GENERATED_VALUE",
    "TPM_ST_ATTEST_QUOTE",
    "QuoteResult",
    "TpmClient",
]
