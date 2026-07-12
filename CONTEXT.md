<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# libattest

Remote-attestation library: produces and verifies attestation Evidence (TPM,
CSR-attestation, key proof-of-possession) and issues Attestation Results, across
the RATS (RFC 9334) role model.

## Language

### RATS roles

**Attester**:
The entity whose environment is being attested; it produces Evidence signed by an
Attestation Key.
_Avoid_: device, client, prover

**Verifier**:
Appraises Evidence against reference values and policy, and issues an Attestation
Result. Signs Results with its own key — never the AK.
_Avoid_: validator, checker

**Relying Party**:
Consumes an Attestation Result and enforces its own acceptance policy. Supplies
the freshness nonce.
_Avoid_: RP-server, consumer

### Tokens

**Evidence**:
Attester-produced, AK-signed claims about an environment (e.g. a TPM2_Quote or
TPM2_Certify statement). The *input* to appraisal.
_Avoid_: attestation, proof

**EAR**:
EAT Attestation Result (draft-ietf-rats-ear-04) — the Verifier-signed result
token, modelled by `EARToken`. The *output* of appraisal.
_Avoid_: result token, verdict token

**Attestation Key (AK)**:
The Attester's signing key over Evidence. On a TPM it is a *restricted* signing
key, so it can only sign TPM-generated data — not an arbitrary JWT/EAT.
_Avoid_: signing key, attestation identity key

### Key binding (draft-reddy-rats-key-binding)

**Subject Key**:
The operational key (used in a CSR or TLS) whose protection properties are being
attested and bound into a token. Distinct from the AK that signs the Evidence.
_Avoid_: application key, user key, target key

**cnf**:
The confirmation claim (RFC 8747 / RFC 7800) that carries the Subject Key's
*public* half, binding it into an EAT/EAR.
_Avoid_: confirmation key, holder key

**key-attributes**:
The draft-reddy-rats-key-binding claim describing how the Subject Key is
protected (`extractable`, `never-extractable`, `sensitive`, `local`, `purpose`).
When backed by a TPM, derived from the certified key's `TPMA_OBJECT` bits.
_Avoid_: key properties, protection flags
