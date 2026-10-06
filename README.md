# libattest-py

> Design inspired by [Mike Ounsworth](https://github.com/ounsworth).

Python helpers for remote attestation flows using Veraison-compatible backends
and the MockCA prototype.

The package provides:

- CMP attestation freshness nonce request/response ASN.1 structures.
- CSR attestation bundle structures (`AttestationBundle`, `AttestationStatement`).
- TPM `TPMS_ATTEST` binary helpers (platform quote parsing).
- `AttesterClient` — dispatch evidence generation to registered providers.
- `AttestClient` — HTTP client for the full Veraison challenge-response flow.
- `VerifierRouter` — in-memory verifier routing by hint, evidence type, or nonce.
- `VeraisonServiceBase` — FastAPI-based abstract base for Veraison-compatible services.
- `libattest.testing.fakes` — in-memory verifier and echo provider for unit tests.
- `libattest.formats.eat_ear.cwt_jwt` — EAR JWT verdict parsing helpers.

> **OID access.** Reference every project OID *only* through the accessors re-exported from
> `libattest`: `get_oid_by_name(name)` (any unambiguous known OID) plus the position-scoped
> `get_oid_for_stmt_name` / `get_nonce_request_oid_for_name` / `get_nonce_response_oid_for_name`.
> Do not import raw OID constants (e.g. `ID_PE_CMW`) or the `resolve_*_oid` helpers directly —
> these functions are the single supported source, keeping OID names and values centralized.
> In particular, `"tpm-quote"` is position-scoped: its nonce-request OID is `1.2.3.4.5`,
> while its nonce-response OID is `1.2.3.4.6`.
> Run `make check-oids` to audit this policy and save the complete findings report to
> `build/oid-access-audit.txt`; format-owned definitions are reported rather than silently ignored.

## NXP demo scope — what this branch proves (and what it does not)

This branch (`demo/docker_RATS_NXP`) is a **mechanism demonstration**, not a
production NXP attestation. Read the boundary before relying on any claim here.

**What it does prove (end-to-end, offline, real execution):**

- The *flow*: NXP-style attestation evidence is generated, wrapped as an
  opaque OID-typed `AttestationStatement`, DER'd into an
  `AttestationBundle`, routed by the CA/RA **on the OID alone** (format-
  agnostic — it never parses the inner bytes), and appraised.
- One fully-verified reference type: **ELE device attestation (0xDB)**.
  `tools/nxp_e2e_offline.py` runs 15 gates — signature verify, RA-nonce
  freshness binding, policy facts, pretty print, debug log — and rejects
  tamper / replay / rogue-anchor.
- The *extend-a-format path*: **ELE key attestation (0x74)** and **SE05x**
  have the same OID registration, decode, and human-readable pretty print,
  showing how a new format plugs in.

**What it does NOT do — do not claim otherwise:**

- It does **not verify** the ELE key-attest (0x74) or SE05x signatures. Those
  `verify_*` functions raise `NotImplementedError` on purpose: the 0x74
  signed-byte schema exists only in closed ELE firmware (NXP's own reference
  test treats the buffer as a black box), and the SE05x anchor is per-chip
  factory data. **Decoding and inspection work; trust does not.**
- The **trust anchor is simulated.** Here the evidence is produced by a Python
  simulator and signed by keys *we* chose — not a real i.MX93 ELE under NXP's
  root. Even the verified dev-attest is verified **only inside the simulated
  trust domain** (see `SimNXP 2GO` in `CONTEXT.md`).
- `imx-secure-enclave` / RM00284 themselves provide **attestation evidence
  generation** (local primitives: `hsm_dev_attest`, `hsm_pub_key_attest`) — a
  signed 280-byte struct or a signed TLV buffer. The device already embeds a
  nonce/challenge *inside* the evidence (`dev_attest.nounce`,
  `key_attest.auth_challenge`), but the repo ships **no verifier, no NXP root
  public key, no RA-side nonce handshake, and no standard token**
  (EAT/COSE/X.509). The remote-attestation layer this package adds on top is:
  wrap as an opaque OID-typed statement → OID route → issue + check the RA
  nonce → verify against an anchor → return a verdict.

One-line honest claim: *this demonstrates how NXP attestation evidence plugs
into a CMP/CSR attestation workflow, with device attestation fully verified as
the reference type and key-attest/SE05x showing the extend path up to the
closed-firmware boundary.*

## Coding Guidelines

See [`GUIDELINES.md`](GUIDELINES.md) — enforced project conventions, most
importantly: generic sign/verify operations go through `keyutils_py` (never
raw `cryptography` ECDSA/RSA calls outside tests), and attestation statements
stay opaque `OCTET STRING`s routed by OID.

---

## Quick Start

Install the package (with optional TPM, verifier-service, and testing extras):

```bash
pip install -e ".[tpm,verifier-service,testing]"
```

Generate evidence on the attester side and verify it locally with the
in-memory fakes:

```python
from libattest.attester.client import AttesterClient
from libattest.testing.fakes import EchoAttesterProvider, InMemoryVerifier
from libattest.verifier.router import VerifierRouter

oid = "1.3.6.1.4.1.99999.1.2"  # evidence-type OID (placeholder)

# Verifier side: register one route by name and evidence-type OID.
router = VerifierRouter()
router.register("tpm", InMemoryVerifier(), evidence_types=[oid], default=True)

# Attester side: register one provider keyed by the same OID.
attester = AttesterClient(providers={oid: EchoAttesterProvider(oid=oid)})

# Challenge → evidence → verdict.
nonce = router.get_nonce(size=32)
result = attester.generate_evidence(oid, nonce=nonce)
verdict = router.verify_token(result.evidence_bytes(), result.media_type, nonce=nonce)
assert verdict.accepted
```

For the full Veraison challenge-response HTTP flow, swap `VerifierRouter`
for `AttestClient` from `attest_client.py` — same `AttestResult` shape,
real REST calls.

---

## Running tests

Local unit tests (no network, no TPM):

```bash
env PYTHONPATH=src python -m unittest discover -s tests
```

With MockCA integration compatibility tests:

```bash
env PYTHONPATH=src:../cmp-test-suite python -m unittest discover -s tests
```

---

## Key Types

### `VerifyResult`

`verify_token()` returns a typed `VerifyResult` instead of `str | None`:

```python
from libattest.types import EarStatus, VerifyResult

result = verifier.verify_token(token_bytes, media_type, nonce=nonce)

if result.accepted:              # True iff status == EarStatus.affirming
    print(result.payload)        # verifier result payload string
else:
    print(result.status)         # EarStatus.contraindicated or EarStatus.unknown
    print(result.errors)         # tuple of error strings
```

Factory class methods:

```python
VerifyResult.affirming("ear-jwt-payload")  # accepted
VerifyResult.contraindicated("sig check failed")  # rejected
VerifyResult.unknown("unsupported media type")   # not evaluated
```

### `AttestResult`

Canonical immutable evidence result shared by `AttesterClient` and `AttestClient`:

```python
from libattest.types import AttestResult

result = AttestResult(
    oid="1.3.6.1.4.1.99999.1.2",        # evidence-type OID (placeholder)
    evidence=b"...",
    media_type="application/vnd.tcg.platform",
    cert_chain="/path/to/chain.pem",   # optional: propagated into bundle certs
)
```

---

## Default Verifier Endpoints

`AttestClient()` targets the standard Veraison deployment by default:

| Endpoint | URL |
|----------|-----|
| Discovery | `http://127.0.0.1:8080/.well-known/verification` |
| New session | `http://127.0.0.1:8080/challenge-response/v1/newSession` |
| Session | `http://127.0.0.1:8080/challenge-response/v1/session/{id}` |
| Provisioning submit | `http://127.0.0.1:8888/endorsement-provisioning/v1/submit` |
| Provisioning session | `http://127.0.0.1:8888/endorsement-provisioning/v1/session/{id}` |

`VeraisonServiceBase` registers the matching route paths automatically.

---

## Optional Dependencies

| Extra | Packages | Purpose |
|-------|----------|---------|
| `tpm` | `tpm2-pytss` | Native ESAPI, `TPMS_ATTEST`, and TPM signature helpers; required by TPM attesters and verifiers, but not by MockCA-only consumers. |
| `verifier-service` | `fastapi`, `uvicorn` | `VeraisonServiceBase` and `verifier_service` module |
| `testing` | `pytest`, `pytest-asyncio`, `httpx` | ASGI test client for FastAPI route tests |

Install with:

```bash
pip install "libattest-py[tpm,verifier-service,testing]"
```
