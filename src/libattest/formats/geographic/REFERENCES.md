<!-- SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0 -->

# References

- [draft-richardson-rats-geographic-results-01 — Geographic Attestation Results](https://datatracker.ietf.org/doc/html/draft-richardson-rats-geographic-results-01)
- [draft-ietf-rats-ear — EAT Attestation Result](https://datatracker.ietf.org/doc/draft-ietf-rats-ear/) (carrier for these claims; see `libattest.ear`)

## Deliberately out of scope

This model is JSON-only and lightly validated, matching the posture of `libattest.ear`:

- **CBOR integer labels** (0..13) are not modelled. The draft's label assignments are
  internally inconsistent in `-01` (e.g. hallway/room both cited at 10/11) and await IANA
  allocation, so the numbers will change. When they stabilize, add a CBOR codec layer
  (see the `Base64UrlBytes` dual-encoding pattern in `libattest.ear`). `near-to` would then
  become a CBOR tag-37 binary UUID rather than the current JSON string.
- **ISO 3166 registry checks** on the country/subdivision fields. Only presence and size
  are enforced, not membership in the code registry.
- **Cross-field rules** — the nesting rule (city ⇒ subdivision ⇒ country) and the
  exclave mutual-exclusivity constraints — are left to the caller. They live in the same
  draft section as the inconsistent labels and are the likeliest to shift in `-02`.
