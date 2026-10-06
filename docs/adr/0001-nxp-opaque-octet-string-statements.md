# ADR 0001: NXP EdgeLock evidence as opaque OCTET STRING statements

- Status: accepted (2026-10-06)
- Deciders: Guiliano (owner), Hermes (author)
- Scope: `libattest.formats.nxp` + the CMP `AttestationBundle` envelope used by
  `cmpClient` (`rats_csr_asn.h`) and the MockCA/RA (libattest.ra)

## Context

The i.MX ELE and SE05x families each produce a *signed native wire format* as
attestation evidence:

| Family | Output | Format |
|---|---|---|
| i.MX ELE device attestation (`hsm_dev_attest`, 0xDB) | 280-byte statement | fixed little-endian C struct (`sab_cmd_dev_attest_rsp_w_data_v2`) |
| i.MX ELE key attestation (`hsm_pub_key_attest`, 0x74) | signed cert buffer | EdgeLock "2GO-TLV" proprietary TLV |
| SE05x attested read (AN13254, `ATTEST` 0x20) | object value + TLV block | EdgeLock TLV, signed by the chip attestation key |

The LAMPS CSR-attestation envelope (`draft-ietf-lamps-csr-attestation-24`)
already carries `AttestationStatement { type OID, stmt ANY }`, and this
codebase's established convention (TPM quote/certify, xclaim-CWT) is: the
attester produces the native bytes, the C side wraps them opaquely, and the
OID-keyed verifier (libattest-py) is the *only* component that parses them.

## Decision

1. All three NXP statement payloads are carried as **opaque
   `OCTET STRING`s** in `stmt`, registered in
   `ATTESTATION_STATEMENT_STRUCTURES` as `univ.OctetString`:
   - `1.3.6.1.4.1.99999.30` — ELE device attestation (280 B LE struct)
   - `1.3.6.1.4.1.99999.31` — ELE key attestation (2GO-TLV)
   - `1.3.6.1.4.1.99999.32` — SE05x attested read (TLV block)
2. Parsing, signature verification, key binding and appraisal live in
   `libattest.formats.nxp` (per-OID codecs), mirroring `formats.tpm.tcg`.
3. The CA/RA stays format-agnostic: it routes by statement OID
   (`VERIFIER_OID_ROUTES` compose env) and never inspects the inner bytes.
4. Human inspection: OID-keyed `pretty_print_nxp_statement(oid, payload)`
   plus `log_statement_debug` (DEBUG level, `libattest.formats.nxp` logger)
   in the verifier.

## Alternatives considered

- **Model each format as a DER ASN.1 structure** (pyasn1 schemas for the
  280-byte struct / 2GO-TLV). Rejected: NXP's bytes are little-endian C
  structs and proprietary TLV, not DER. Re-encoding would (a) break the
  attester's signature, which is computed over the exact native bytes, and
  (b) make real `se_tools` / `se05x` output non-interchangeable with
  simulator output. The OID→codec indirection gives us the same machine
  readability (and the prettyPrint) without changing the wire.
- **A common NXP wrapper SEQUENCE** (e.g. `{ soc_id, fw_sha, … }` re-derived
  from both families). Rejected: it would require the CA/RA (or the
  attester) to interpret family-specific fields — the exact coupling we are
  removing — and it is lossy for fields the wrapper doesn't name.

## Consequences

- Adding a new NXP family/format = new OID + new codec + verifier profile;
  zero CA/RA code change.
- The 2GO-TLV key-attest cert tag map is *not* fully published in the open
  material we can cite; `ele_key_attest.py` therefore walks the TLVs
  format-agnostically and labels known tags best-effort, surfacing unknown
  tags verbatim (never dropped). Correcting the tag map later is a one-line
  change to `KNOWN_2GO_TAGS`.
- The ELE device-attest codec is byte-exact against
  `imx-secure-enclave @ 46384506` (`sab_dev_attest.h`) and verified by
  `tests/test_nxp_dev_attest_codec.py` against a generated 280-byte
  statement (decode, signature verify, tamper rejection).
- Trust-domain caveat: with the simulator (SimNXP 2GO) the anchor is
  simulator-generated; with real hardware the anchor is NXP's 2GO/EdgeLock
  CA chain. The codec is agnostic to which (pinned root PEM is verifier
  config).
