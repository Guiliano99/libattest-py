<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# key-attributes are derived by the Verifier from the certified public area

The draft's `key-attributes` (`extractable`, `never-extractable`, `sensitive`,
`local`, `purpose`) could be *asserted by the Attester* or *derived by the
Verifier*. We derive them in the Verifier from the `TPMA_OBJECT` bits of the
`TPM2_Certify`-covered `TPMT_PUBLIC`, so they reflect what the TPM enforces rather
than what the Attester claims. An Attester cannot inflate its key's protection:
the bits were signed by the AK as part of the certified Name/public area.

Mapping (see `prototypes/tpm_key_binding/key_attributes.py`): `never-extractable`
← `fixedTPM`; `extractable` ← `not fixedTPM`; `sensitive` ← `fixedTPM`;
`local` ← `sensitiveDataOrigin`; `purpose` ← `SIGN_ENCRYPT`/`DECRYPT`.
Extractability keys off `fixedTPM` (the transitive "never leaves this module"
property), **not** `fixedParent` (which only blocks direct re-parenting of one
object and is unsafe as an extractability signal).

## Consequences

Relying-Party policy (`KeyBindingPolicy`) is evaluated against these
Verifier-derived attributes. The mapping is a normative interpretation of the
draft in TPM terms — if the draft or the TPM attribute semantics change, this
mapping is the single place to revisit.
