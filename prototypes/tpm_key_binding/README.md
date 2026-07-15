<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# TPM-backed key attestation (`draft-reddy-rats-key-binding-01`)

A prototype that generates and verifies a **key-binding attestation token** by
combining [`draft-reddy-rats-key-binding-01`](https://www.ietf.org/archive/id/draft-reddy-rats-key-binding-01.txt)
("Key Attestation for EAT") with a **TPM 2.0**, reusing this repo's existing TPM,
JOSE, and EAR building blocks.

The problem the draft solves is a **key-substitution attack**: an endpoint could
present valid attestation for a protected environment while submitting a CSR/TLS
key that was *not* generated or protected there. Key binding cryptographically
ties the operational key to the attested environment.

## What this produces

Two tokens, at the two points in the RATS pipeline where they belong:

1. **Evidence** (Attester → Verifier): a TPM `TPM2_Certify` of the Subject Key,
   which is the AK-signed proof of the key's protection properties.
2. **Attestation Result / EAR** (Verifier → Relying Party): an
   [`EARToken`](../../src/libattest/ear.py) (draft-ietf-rats-ear-04) whose
   `KEY_BINDING` submodule carries the appraised **`cnf`** (RFC 7800 confirmation
   key) and **`key-attributes`** (draft §3), signed with the Verifier's ES256 key.
   The EAR is emitted in the repo's dotted wire dialect (`ear.status`,
   `ear.attester-claims`, …), so `libattest.formats.eat_ear.cwt_jwt.ear_is_affirming` /
   `parse_ear_verdict` read it directly.

```
Attester (TPM)                         Verifier                        Relying Party
──────────────                         ────────                        ─────────────
create Subject Key                     issue nonce  ───────────────▶
TPM2_Certify(subject, AK, nonce)  ─── Evidence ───▶  verify AK sig
subject-key PoP over nonce                          check certify Name == H(TPMT_PUBLIC)
                                                    objectAttributes → key-attributes
                                                    enforce RP policy
                                                    verify PoP against cnf
                                                    build + sign EAR  ── EAR (cnf, key-attributes) ─▶
```

## The one design decision that matters: A1 (native certify)

The draft says *"the Attester signs the EAT using the Attestation Key."* **A TPM
AK cannot do that literally** — it is a *restricted* signing key (see
`_ak_template` in `attester/tpm_client.py`), so the TPM will only let it sign data
the TPM itself generated (prefixed with `TPM_GENERATED_VALUE`), never an arbitrary
JWT/EAT payload.

So "AK signs the EAT" is realised as **design A1**: the AK-signed
`TPM2_Certify` output *is* the Evidence. Its `TPMS_ATTEST` (type
`TPM_ST_ATTEST_CERTIFY`) binds the AK to the **Name** of the Subject Key, and the
Verifier derives `cnf` and `key-attributes` from the certified `TPMT_PUBLIC`.
This reuses the repo's existing `TcgAttestCertify` structure (OID `2.23.133.20.1`),
so the Evidence rides in an ordinary `AttestationBundle`
(`KeyBindingEvidence.certify_der()`).

> The alternative (A2) — a *separate, non-restricted* device identity key that
> signs a real JWS EAT — is a small extension: swap the software AK for two keys.
> A1 was chosen because it reuses the most existing code and keeps every claim
> anchored in what the TPM actually enforces.

## Mapping TPM object attributes → draft `key-attributes`

The verifier reads `TPMA_OBJECT` from the **certified** `TPMT_PUBLIC` (offset 4),
so the Attester cannot lie about them (`key_attributes.py`):

| draft `key-attributes` | TPM `TPMA_OBJECT` source | meaning |
| --- | --- | --- |
| `never-extractable` | `fixedTPM` | private part can never leave *this* TPM |
| `extractable` | `not fixedTPM` | not TPM-bound ⇒ exfiltratable (see note) |
| `sensitive` | `fixedTPM` | private value is never exposed in the clear |
| `local` | `sensitiveDataOrigin` | the TPM generated the key (it was not imported) |
| `purpose` | `SIGN_ENCRYPT` / `DECRYPT` | `tpm:sign` / `tpm:decrypt` |

> **Why `extractable ← not fixedTPM`, not `not fixedParent`:** `fixedTPM` is the
> *transitive* "never leaves this module" property (a key may set it only if its
> parent has it too). `fixedParent` merely blocks direct re-parenting of one
> object — a key with `fixedParent` set but `fixedTPM` clear still lives under a
> duplicable parent and can be exfiltrated by duplicating that parent, so it must
> be reported extractable.

A Relying-Party `KeyBindingPolicy` (draft §5.2/§6) then enforces, by default,
`never-extractable = true`, `local = true`, and `extractable = false`.

## Verifier checks (all six must pass)

1. `TPMS_ATTEST` is TPM-generated and a **certify** (`TPM_ST_ATTEST_CERTIFY`).
2. **AK signature** verifies over the exact statement (`verify_tpm_signature`).
3. `extraData == expected_nonce` (**freshness**).
4. certified **Name** `==` `compute_tpm_name(TPMT_PUBLIC)` (**anti-substitution**).
5. `key-attributes` derived from the certified area satisfy **RP policy**.
6. **proof-of-possession** verifies against `cnf` (the operational key *is* the
   certified key — draft §5.2 step 5).

## Run it

```bash
# from the repo root, using the project venv
.venv/bin/python prototypes/tpm_key_binding/demo.py            # software path, no TPM
.venv/bin/python -m pytest prototypes/tpm_key_binding/ -q      # 10 offline checks
```

Real TPM (the [`docker/tpm-demo`](../../docker/tpm-demo) swtpm, or `/dev/tpmrm0`):

```bash
LIBATTEST_TCTI=mssim:host=127.0.0.1,port=2321 .venv/bin/python prototypes/tpm_key_binding/demo.py
```

## Files

| file | role |
| --- | --- |
| `key_attributes.py` | draft `key-attributes` model + `TPMA_OBJECT` mapping + RP policy |
| `evidence.py` | `KeyBindingEvidence` (the certify triple + AK key + PoP) |
| `attester.py` | `SyntheticKeyBindingAttester` (no TPM) and `TpmKeyBindingAttester` (real) |
| `verifier.py` | `KeyBindingVerifier` — the six checks + EAR issuance |
| `demo.py` / `test_key_binding.py` | runnable demo and offline self-test |

## What is real vs. faked in the software path

The synthetic Attester mints **genuine TPM wire structures** — a real marshalled
`TPMT_PUBLIC` (via `TPM2B_PUBLIC.from_pem`, embedding a real EC point with chosen
`objectAttributes`) and a real `TPM_ST_ATTEST_CERTIFY` `TPMS_ATTEST`. Only the
**AK signature** (a software EC key instead of a restricted TPM AK) and the
hand-marshalled certify blob are software-produced. Every byte the *Verifier*
inspects is TPM-shaped, so the self-test exercises the production verifier logic.

## Limitations / next steps (prototype)

- **AK trust is assumed.** `ak_public_spki` is taken as already trusted. A real
  deployment binds the AK to an EK via credential activation — which this repo
  *already implements* (`key_attest_pop` + `TpmClient.activate_credential`); wire
  that in front of step 2.
- **EC P-256 only** for Subject/AK/EAR keys (matches the repo's JWK helpers). RSA
  Subject Keys are analogous (`cnf` becomes an RSA JWK).
- `purpose` uses illustrative `tpm:sign`/`tpm:decrypt` labels; the draft specifies
  `[* oid]`, so a real profile maps to concrete key-purpose OIDs.
- The real-TPM path (`TpmKeyBindingAttester`) is **not** covered by the offline
  self-test; exercise it against the swtpm as shown above.
