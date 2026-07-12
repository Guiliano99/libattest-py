<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# Key binding uses native TPM2_Certify Evidence, not an AK-signed EAT (design "A1")

`draft-reddy-rats-key-binding` says the Attester signs the key-binding EAT with
its Attestation Key. A TPM AK is a **restricted** signing key, so the TPM refuses
to let it sign arbitrary application data such as a JWT/EAT — it will only sign
data the TPM itself generated. We therefore realise "AK-signed Evidence" as the
AK-signed **`TPM2_Certify`** output (`TPMS_ATTEST` of type
`TPM_ST_ATTEST_CERTIFY`): it binds the AK to the Subject Key's Name, and the
Verifier lifts `cnf` + `key-attributes` from the certified `TPMT_PUBLIC` into the
EAR. This reuses the existing `TcgAttestCertify` structure and keeps the
restricted AK.

## Considered options

- **A1 — native certify (chosen).** Maximum reuse; every claim is anchored in
  what the TPM enforces; no second key to manage.
- **A2 — two keys.** A separate *non-restricted* device identity key signs a real
  JWS EAT (literal draft shape), while a restricted AK certifies the key. More
  faithful to the draft's wire form, but adds a key and more trust plumbing.
  Recorded as the documented extension path, not implemented.

## Consequences

The prototype's Evidence is a DER `TcgAttestCertify`, not a JWS EAT; the `cnf` and
`key-attributes` claims first materialise in the Verifier-issued EAR, not in the
Attester's Evidence.
