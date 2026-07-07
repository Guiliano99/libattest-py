<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# TPM 2.0 quote wire-format stays pytss-free; consolidate the PCR/hash respInfo codecs

`formats/tpm/*` (including the new `quote_profile.py` and `tcg.py`) models the
nonce-freshness `reqInfo`/`respInfo` wire format and `AttestationStatement`
evidence container for the TPM 2.0 quote profile. `attester/tpm_client.py` is
the sole module that imports `tpm2_pytss` and drives real ESAPI/TPM2 commands
(`TPM2_Quote`, `TPM2_Certify`). We keep that split: `formats/tpm/*` never
imports `tpm2_pytss`, so it stays usable on CA/verifier hosts with no TPM
present. Wiring a real `TPM2_Quote` result (from `TpmClient.quote()`) into
`prepare_tcg_attest_certify` is separate follow-up work, not part of this
change.

Before this change, three parallel ASN.1/JSON codecs existed in
`formats/tpm/` for the same PCR-selection + hash-algorithm negotiation
concept: `pcr_selection.py` (`TpmPcrSelectionInfo`, OID + JSON-in-UTF8String),
`attestation_params.py` (`TpmAttestationParams`, DER `{pcrs?, hashAlgId?}`),
and the new `quote_profile.py` (`TPM20QuoteReqInfoASN1`/`RespInfoASN1`, DER
`{certificateName?, pcrSelection, hashAlgo}`). `respinfo.py`'s registry now
routes exclusively through `quote_profile.py`. `attestation_params.py` and
`pcr_selection.py`'s value-encoding functions (not its still-live
`resolve_tpm_pcr_selection_oid`/`TPM_PCR_SELECTION_OID_*` OID lookup) are
deleted rather than deprecated-in-place, since nothing outside their own test
files referenced them and this repo does not keep backwards-compat shims for
unreferenced code.

`TcgAttestQuote` (a `TcgAttestCertify` subclass with no new fields, plus a
byte-for-byte duplicate `prepare_tcg_attest_quote`) is dropped. TPM2_Certify
and TPM2_Quote evidence share one wire shape; which command produced the
bytes is carried by the outer `AttestationStatement.type` OID
(`2.23.133.20.1` vs `2.23.133.20.2`), not by a distinct pyasn1 type —
`decode_tcg_attest_certify`'s own docstring already documented this before
`TcgAttestQuote` was added. Evidence for either command is built with
`prepare_tcg_attest_certify`/`decode_tcg_attest_certify`.

`PCRIndex` in `quote_profile.py` is constrained to `0..23` (not `0..255`),
matching `pcr_selection.py`'s existing rationale: TPM 2.0's
`TPMS_PCR_SELECTION.sizeofSelect` addresses at most 24 PCRs per bank on every
shipping TPM.

## Known, deliberately deferred issues

* `id_tpm20_quote_req`/`id_tpm20_quote_res` (`1.2.3.4.5`/`1.2.3.4.6`) are
  placeholder OIDs, not delegated to any real registrant — same class of
  issue the nonce-freshness OIDs had before this change moved them to the
  PKIX arc (`1.3.6.1.5.5.7.4.98`/`99`). Real OIDs are assigned later.
* `TPM20QuoteReqInfoASN1`'s two `OptionalNamedType` fields (`certificateName`,
  `supportedHashAlgo`) both carry the plain universal SEQUENCE tag with no
  explicit tagging, so `der_decoder.decode(der, asn1Spec=TPM20QuoteReqInfoASN1())`
  raises `pyasn1.error.PyAsn1Error: Duplicate component tag`. Confirmed by
  direct execution, not just inspection. `decode_tpm20_quote_req_info` works
  around this by decoding as a bare `univ.Sequence()` and sniffing the first
  inner element's tag (`_decode_request_component`) instead of decoding
  against the typed spec — unlike `decode_tpm20_quote_resp_info`, which
  decodes directly against `TPM20QuoteRespInfoASN1()` without a workaround.
  The standard fix (explicit `implicitTag=tag.Tag(tag.tagClassContext, ...)`
  per optional field, already used in
  `csrattest/csr_attest_structures.py:43-44`) was proposed and declined for
  now; `TPM20QuoteReqInfoASN1` remains undecodable via its own asn1Spec.

## Consequences

`formats/tpm/` has one respInfo/reqInfo codec for the TPM 2.0 quote profile
instead of three. A future change that wires real `TPM2_Quote` output into
evidence construction only needs to add code in `attester/`, not touch
`formats/tpm/`. The two deferred issues above should be revisited before this
profile is used outside test/prototype contexts: an unassigned OID risks
collision with another implementation's private arc, and the tag-collision
bug means any external tool that (correctly, per pyasn1/ASN.1 convention)
tries to decode `TPM20QuoteReqInfo` against its declared spec will fail.
