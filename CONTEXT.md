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

**EAT Claims Set**:
The typed Evidence claims-set a device produces (RFC 9711 §4 — `ueid`, `measurements`,
`uptime`, `dbgstat`, …), modelled by `EATClaimsSet`. The Evidence-side counterpart to
`EARToken`: Evidence in, appraisal, EAR out. Byte-valued claims share the same
`Base64UrlBytes` / `EATNonce` types as the EAR model. Distinct from the raw *CWT Claim Set*
(the untyped CBOR map) below.
_Avoid_: EAT token, evidence blob

**CWT Claim Set**:
The CBOR map of CWT claims, keyed by integer claim labels. It is a claims
representation, not by itself a signed or encrypted token.
_Avoid_: CWT token, COSE message

**JWT-style View**:
A readable JSON object rendered from CWT/EAT claims. It is not a compact JWS
and carries no signature by itself.
_Avoid_: JWT, signed token

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

### Wire formats

**CMW**:
The RATS Conceptual Message Wrapper (draft-ietf-rats-msg-wrap) is an
encapsulation for one or more conceptual messages. A Record or Collection has
equivalent JSON and CBOR serializations; its selected serialization determines
how the contained message bytes are represented. Its DER encoding is an
`AttestationStatement.stmt` value (a *statement payload*), not an entire
`AttestationStatement`; the caller supplies the statement type OID and envelope.

**Statement**:
An OID-tagged ASN.1 `ANY` payload whose concrete pyasn1 type is selected
purely by its accompanying OID — never by content inspection. Appears in
three wire positions: `AttestationStatement.stmt` (carries Evidence),
`NonceRequestTypeInfo.reqInfo`, and `NonceResponseTypeInfo.respInfo` (both
CMP nonce-freshness handshake payloads, exchanged before Evidence exists).
`_Avoid_`: payload, blob
