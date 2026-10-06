# Coding Guidelines

Project conventions for contributors to `libattest-py`. These are enforced
expectations, not suggestions — new code is reviewed against them.

## 1. Key operations: use `keyutils_py`, not raw `cryptography`

All **generic** (i.e. not TPM-specific and not vendor-device-specific)
signing and verification operations — the kind a Python script would write
with the `cryptography` library directly — MUST go through the
[`keyutils-py`](https://github.com/Guiliano99/keyutils-py) package
(declared in `pyproject.toml`, `keyutils-py @ git+...`).

```python
from keyutils_py import sign_data, verify_signature

sig = sign_data(data, private_key, hash_alg="sha384")      # -> bytes
verify_signature(public_key, sig, data, hash_alg="sha384") # raises InvalidSignature
```

- Positional argument order follows `cryptography`:
  `sign(data, key, hash_alg)` / `verify(pub, signature, data, hash_alg)`.
- `hash_alg` is a string name (`"sha256"`, `"sha384"`, ...); keyutils resolves it.
- **Why**: one dispatch point for traditional (EC/RSA/DSA/EdDSA) and post-
  quantum key types, one test surface, one place to add algorithm support.

**What is NOT covered (stays in the owning module):** device-specific wire
layout and algorithm binding. For example, the NXP ELE dev-attest codec
keeps its 280-byte canonical-buffer layout and fixed-width `r||s` (96-byte)
signature construction in `libattest/formats/nxp/ele_dev_attest.py` — only
the underlying ECDSA verify call is routed through `keyutils_py`. Same for
TPM: `TcG` structures stay in `formats/tpm/`, only the signature check is
generic.

Checklist when adding sign/verify code:

- [ ] Is the operation a plain "sign/verify these bytes with this key" with
      no device-specific framing? → **must** use `keyutils_py`.
- [ ] Does it involve a vendor wire format (fixed-width signatures, TLV
      composition, canonical buffers)? → framing in the format module,
      primitive via `keyutils_py`.
- [ ] Do you find yourself importing `cryptography.hazmat.primitives.asymmetric.ec.ECDSA`
      (or `rsa.PSS` / `hashes` for a signature) outside a test? → stop, route
      through `keyutils_py`.

## 2. Attestation statements: opaque, OID-routed

- Statement payloads are carried as `OCTET STRING` in the LAMPS
  `AttestationStatement { type OID, stmt ANY }` envelope; the OID is the
  single routing key. See `docs/adr/0001-nxp-opaque-octet-string-statements.md`.
- The CA/RA never inspects the inner bytes; per-format parsing lives in
  `libattest/formats/<family>/` and is keyed by OID.
- Human-readable inspection is done by the family's pretty API
  (e.g. `libattest.formats.nxp.pretty_print_statement`), which decodes the
  ASN.1 envelope itself; callers pass the wire form, never a pre-split
  `(oid, payload)` pair.

## 3. Errors and logging

- Format codecs raise the family's `*Error` (subclass of `ValueError`) for
  malformed payloads — never bare exceptions with offsets in the message.
- Decoding logs at `DEBUG`/`WARNING` under `libattest.formats.<family>`;
  prettyPrint helpers never log at `INFO` and above.

## 4. Tests

- Codec changes ship with a self-test that round-trips a real (or
  simulator-generated) wire payload: decode → re-derive canonical bytes →
  verify → tamper-reject.
- Signature conventions are asserted **empirically** (single vs. double
  hashing is a real trap): the test must fail if the convention drifts.
