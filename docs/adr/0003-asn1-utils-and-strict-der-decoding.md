<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# Shared strict-DER codec in `libattest.asn1_utils`; TPM20QuoteReqInfo gains implicit tags

> **PARTIALLY REVERTED (2026-07-14):** The `TPM20QuoteReqInfo` `[0]`/`[1]` IMPLICIT
> retag below was **reverted to the historical universal `SEQUENCE OF` form**.
> Rationale: the gencmpclient C encoder (`i2d_TPM20_QUOTE_REQ_INFO`) still emits the
> untagged form, and retagging the C side never happened, so the retag left
> libattest unable to decode the reqInfo every demo actually sends (the new
> `cli.py` / `parse_genm_pkimessage` crashed on it). `TPM20QuoteReqInfoASN1` now
> carries universal tags again; the two OPTIONAL fields are disambiguated by their
> inner element type (`UTF8String` vs `INTEGER`) in `decode_tpm20_quote_req_info`
> (+ `decode_tpm20_quote_req_info_asn1` for a display object), restoring the
> manual-disambiguation decoder this ADR had removed. The `asn1_utils` codec
> consolidation (the ADR's primary decision) stands. Golden vector
> (`test_tpm20_quote_golden.py::REQ_GOLDEN`) updated to the universal form; the
> byte-for-byte C interop guarantee is now restored rather than pending a C retag.


Every format module that decodes a Statement (`AttestationStatement.stmt`,
`reqInfo`, or `respInfo` — see `CONTEXT.md`) had its own copy of "DER-decode
against a pyasn1 spec, reject trailing bytes, wrap pyasn1's exception zoo as
`ValueError`". Seven modules duplicated this block; three of them
(`x509/extensions.py::decode_cmw_json_record`,
`eareat_hpke.py::parse_evidence_enc_nonce_response`, and an inline decode in
`verifier/router.py`) had silently drifted from the pattern — they didn't check
for trailing bytes, so malformed input past the first valid TLV was silently
accepted. We hoisted the pattern into `libattest.asn1_utils.try_decode_pyasn1`
(paired with `encode_to_der`) and migrated every DER decode/encode call site in
the library onto it.

## Placement

`asn1_utils.py` lives at the `libattest` package root, not inside `formats/`,
because two of the duplicate sites (`x509/extensions.py`, `verifier/router.py`)
sit outside `formats/` and need to reach it without an upward import.

## Consequences

- **Behavior tightened, not just deduplicated.** The three drifted sites above
  now reject trailing bytes and raise `ValueError` uniformly, matching every
  other decoder in the library. A caller that was previously tolerating (and
  silently discarding) trailing bytes after a CMW record, an HPKE nonce
  response, or an attestation bundle will now see a `ValueError` instead.
- **`verifier/router.py`** no longer re-decodes `AttestationBundle` inline; it
  calls the existing `decode_attestation_bundle()` from `csrattest`, removing a
  second, weaker implementation of the same decode.
- **`TPM20QuoteReqInfoASN1` gained implicit context tags** (`[0]`/`[1]` on
  `certificateName`/`supportedHashAlgo`). Both fields are `OPTIONAL` and, as
  originally declared, shared the same untagged universal `SEQUENCE` tag —
  ASN.1 (X.680 §8) requires distinguishing tags for this exact shape, and
  without them pyasn1's automatic named-type decoder cannot tell which
  optional field a given `SEQUENCE`-tagged component is, and raises
  unconditionally regardless of which field is actually present. The class had
  been defined but never exercised for decode; a hand-written decoder
  (`decode_tpm20_quote_req_info`) worked around the ambiguity by inspecting
  each component's first inner element's tag instead of using the schema.
  Retagging replaces that workaround with ordinary structure-driven decoding
  via `try_decode_pyasn1`, at the cost of a **wire-format break**: the DER
  bytes for `TPM20QuoteReqInfo` no longer match the historical untagged form
  emitted by the `gencmpclient` C reference encoder
  (`i2d_TPM20_QUOTE_REQ_INFO`). `tests/test_tpm20_quote_golden.py`'s
  `REQ_GOLDEN` vector was updated to the new (Python-only) bytes; the C side
  needs the equivalent `[0]`/`[1]` IMPLICIT retag before cross-language
  byte-for-byte interop is restored. `TPM20QuoteRespInfo`'s golden vector is
  untouched — its fields (`certificateName`, `pcrSelection`, `hashAlgo`) don't
  share tags and were never ambiguous.
- **Request/response Statement maps are now symmetric.** `stmt_mappings.py`
  gained `NONCE_REQUEST_STATEMENT_STRUCTURES` /
  `get_nonce_request_statement_structure()`, mirroring the response side. The
  older `get_nonce_request_statement_decoder()` /
  `nonce_request_statement_decoders()` are kept for compatibility, reimplemented
  as thin closures over `try_decode_pyasn1` and the new structure map — but
  they now return a generic decoded pyasn1 object, not the
  `(names, algos)`-shaped tuple `decode_tpm20_quote_req_info` used to return
  directly. Callers that need that specific semantic shape (e.g.
  `pretty_print_stmt.py`) call `decode_tpm20_quote_req_info` directly instead
  of going through the generic accessor.
