<!-- SPDX-FileCopyrightText: Copyright 2026
SPDX-License-Identifier: Apache-2.0 -->

# Changelog

## Unreleased (Updatev7)

- **Prune dead code / dedupe ASN.1 names.** Remove the never-called
  `AttestClient.generate_evidence_from_cmp_nonce_responses()` and the unused
  `NonceRequestValue` / `NonceResponseValue` SEQUENCE-OF compatibility wrappers
  (each nonce message now carries a single nonce), and collapse the duplicated
  `NonceRequestASN1` / `NonceResponseASN1` names into the canonical
  `NonceRequest` / `NonceResponse` (the `*ASN1` aliases are removed). Also drop a
  dead `der_encoder` round-trip in `verifier/router.py` and the stale commented-out
  `cwt` dependency.
- **Delegate `KeyAttestPoP` signing/verification to `keyutils-py`.** Add
  `keyutils-py` (git `main`) as a dependency and route `compute_key_attest_pop()` /
  `verify_key_attest_pop()` through `keyutils_py.sign_with_alg_id()` /
  `keyutils_py.verify_signature_with_alg_id()` for both RSA (PKCS#1 v1.5) and ECDSA,
  replacing the hand-rolled `cryptography` padding/hash dispatch. Key loading stays
  on `cryptography` (keyutils-py has no in-memory SPKI/DER loader); the TPM-quote and
  EAR-JWT verifiers keep their raw-`r‖s` `cryptography` paths. RSA PoP signatures are
  byte-identical to before. The `docker/tpm-demo` client image now builds its venv on
  Python 3.13 (deadsnakes PPA) and installs `keyutils-py`, since keyutils-py requires
  Python &gt;=3.13 (Ubuntu 24.04 ships 3.12).
- **Make `tpm2-pytss` a mandatory dependency** (added to `[project]`
  dependencies) and consolidate the TPM quote model. `formats/tpm/tpms_attest.py`
  is now the single source of truth for the TPM constants / algorithm ids (sourced
  from the pytss enum), the one `parse_tpms_attest()` parser, and the
  `TpmQuoteSignatureEvidence` producer→verifier seam — built in one call via
  `QuoteResult.to_evidence()` instead of hand-copying five fields. The attester
  and verifier import these instead of redefining them, and the defensive
  `try/except ImportError` + `pytest.importorskip("tpm2_pytss")` guards are
  removed (pytss is always present). Supersedes the "optional `tpm2-pytss`" notes
  below.
- **Remove the `libattest.simulator` package.** The platform and key-attestation
  demos now live as self-contained scripts in `docker/tpm-demo/`
  (`platform_attest_demo.py`, `key_attest_demo.py`, launched by `demo.py`) and
  are tested by `docker/tpm-demo/test_demo.py`. The unused `SimulatorStack`
  (docker-compose driver) and `VerifierClient` (Veraison HTTP client) helpers are
  deleted. Supersedes the "`SimulatorStack` … remain" note below.
- Add `libattest.attester.tpm_client` (`TpmClient` / `QuoteResult`): a real
  tpm2-pytss ESAPI device client (EK/AK provisioning, `TPM2_Quote`, credential
  activation) for driving the bundled `docker/tpm-demo` simulator. The module
  requires the optional `tpm2-pytss` package; the rest of `libattest.attester`
  still imports without it.
- Rewire the `libattest.simulator` key/platform demos to perform **real** TPM
  attestation via `attester.tpm_client` (real `TPM2_Quote` and credential
  activation) verified through libattest's own verifiers, replacing the previous
  `tpm2-tools` probe + pure-Python fallback. The demos and
  `tests/test_simulator_demos.py` require `tpm2-pytss` + a live TPM (they run in
  the `docker/tpm-demo` client container and skip cleanly elsewhere).
- Consolidate the simulator on the real pytss client: remove the orphaned
  tpm2-tools shell-out `simulator.TpmClient` and `simulator/tpm_tools.py` (and
  their test), now superseded by `attester.tpm_client`.
- Simplify the `docker/tpm-demo` images: realign the Dockerfiles with the
  upstream reference for readability/correctness, and drop the unused
  `tpm2-tools` layer + `TPM2TOOLS_TCTI` env (the demos use tpm2-pytss only).
- Parse `TPMS_ATTEST` via `tpm2_pytss.TPMS_ATTEST.unmarshal` instead of the
  hand-rolled `struct` parser. `formats/tpm/tpms_attest.py` now exposes a single
  `parse_tpms_attest()` → `ParsedAttest` (replacing `extract_qualifying_data` /
  `extract_quote_info`), so `TpmPlatformVerifier` parses the buffer once rather
  than three times, and the `TPM_GENERATED_VALUE` / `TPM_ST_ATTEST_QUOTE`
  constants are centralized there. `tpm2-pytss` is a mandatory dependency
  (imported unconditionally at module load), and the platform-quote appraisal
  tests run in the `docker/tpm-demo` container.
- Remove the unused `libattest.crypto` package (RSA-encrypted-challenge /
  RSAES-OAEP helpers) and drop the `keyutils_py` dependency. The v5 key
  attestation signs the activation `seed`; it never used RSA-encrypted or
  PBMAC challenge forms.
- Remove the now-dead `AttestResult.is_asn1_evidence` flag — its only consumer
  was the removed `TPM2_Certify` ASN.1-embedding path; all evidence is wrapped
  as an opaque OCTET STRING.
- Remove the legacy `TPM2_Certify` key-attestation mechanism, superseded by the
  v5 challenge-bound `KeyAttestPoP` proof-of-possession flow
  (`libattest.formats.key_attest_pop`). Deletes `formats/tpm/tcg.py`
  (`TcgAttestCertify`, `id_tcg_attest_certify`, `prepare_tcg_attest_certify`),
  `formats/tpm/tpm_name.py` (`compute_tpm_name`), `extract_certify_name`
  (`tpms_attest.py`), `prepare_asn1_attestation_statement` (`csrattest`), and the
  stale `application/vnd.tcg.attest-certify` media type. Platform (`TPM2_Quote`)
  attestation and the shared `TPMS_ATTEST` helpers are unaffected.
- Add typed ASN.1 `TpmAttestationParams` codec
  (`libattest.formats.tpm.attestation_params`) for `NonceRequest.reqInfo` /
  `NonceResponse.respInfo`, wire-compatible with the OpenSSL/gencmpclient
  `LOCAL_TPM_ATTESTATION_PARAMS` implementation. The JSON
  `TpmPcrSelectionInfo` wrapper remains available as an alternative encoding.
- Add `TpmPlatformVerifier.appraise_quote()` running the full platform
  appraisal in one call: structural/freshness/signature checks plus the
  PCR-selection binding check and reference-digest comparison.
- Add `pcr_mask_to_indices()` / `pcr_indices_to_mask()` helpers for the
  TPM-native `TPMS_PCR_SELECTION.pcrSelect` bitmask encoding.
- Add `find_attestation_statements()` to look up `AttestationBundle`
  statements by type OID.
- Update `TPM2_PLAT_ATTEST_DESIGN.md` against current drafts: typed
  `TpmAttestationParams` profile for reqInfo/respInfo, corrected zero-length
  nonce semantics (freshness PR #26), `id-it` OID arc note, and
  `LimitedCertChoices` / `id-aa-attestation` alignment with
  draft-ietf-lamps-csr-attestation-27.

## 0.0.1

- Created
