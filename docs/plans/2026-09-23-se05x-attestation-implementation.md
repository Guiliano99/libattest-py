<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# SE05x attestation: implementation plan

Status: implemented 2026-09-24 as private, uncommitted changes; all quality gates pass (unit
suite, ruff, pyright, `make check-oids`, REUSE on the new files, pylint gate, `make se05x-test`,
`make se05x-demo`). Decisions and their evidence:
[`2026-09-23-se05x-freshness-nonce-length.md`](2026-09-23-se05x-freshness-nonce-length.md)
(below: *the decision report*). Exploration artifacts: `<artifacts>` =
`~/.claude/projects/-home-debian-PycharmProjects-libattest-ra-wt/ea415bc2-8b08-4949-8d24-9431fa54a9b9/se05x-spike-artifacts/`.

## Goal

An NXP SE05x attestation profile for libattest, demonstrated end to end against a patched wolfSSL
SE050 simulator in a fresh Docker Compose stack, and shaped so that a later **CMP end-to-end
example** can use it without changing libattest:

1. The RA issues a 16-byte nonce for the SE05x request type.
2. The Attester generates a P-256 key inside the SE, reads it with attestation (freshness = the
   nonce, unchanged), and packs the Evidence into an `AttestationBundle` with the attestation
   certificate chain.
3. The RA's `RemoteAttestationEngine.verify_bundle(bundle, tx_id, pubkey=<CSR key>)` routes the
   statement to the SE05x verifier through the SE05x profile.
4. The verifier appraises the Evidence and issues an EAR with AR4SI trust claims; the RA's
   `EarAcceptancePolicy` verifies the EAR against the verifier's pinned key.
5. For CMP later: the SE-generated key can sign a CSR through the SE (`Se05xClient.sign_digest`),
   and the EAR goes into the issued certificate through the profile's existing EAR-extension
   encoder.

## Decisions (all 2026-09-23)

| Topic | Decision |
|---|---|
| Visibility | private, local changes only: no commit unless asked, no push, no pull request, no upstream offer of the simulator patch (2026-09-24) |
| Simulator | wolfSSL SE050Sim, upstream `ee28091` + PR #19 as two vendored patches + our attestation patch; all GPL-3.0-or-later, in `docker/se05x-demo/sim/`, REUSE-annotated |
| Response format | applet 7.2 only; the 3.1.1 personality refuses attested reads |
| Attestation key | `0xF0000012`, P-256, policy READ + ATTESTATION, origin PROVISIONED; **random per start**, `SE050_SIM_ATTEST_SEED` makes it deterministic |
| Chip id | `0x7FFF0206`, 18 bytes, READ only, origin PROVISIONED |
| Certificate | one-shot `provision` service mints `0xF0000013` from a demo root named `libattest demo SE05x attestation root (not NXP)`; the root private key never leaves that container; only the root certificate is shared |
| Subject | a P-256 key pair generated inside the SE |
| Nonce | 16 bytes, sent unchanged as `TAG_7`; `NonceStore(nonce_bytes=16)`; attester omits `NonceRequest.len` and fails closed on any other length |
| Evidence | `Se05xAttestEvidence ::= SEQUENCE { commandApdu OCTET STRING, responseBody OCTET STRING }`; no nonce field, no algorithm copy |
| Algorithm | ECDSA with SHA-256 (`0x21`) only in the verifier |
| Command shape | verifier accepts exactly TLVs `41 45 46 47` (key-pair read) |
| No-READ targets | simulator answers without `TAG_1`; the verifier rejects that |
| EAR | issued by the SE05x verifier, checked by the RA; verdict **plus AR4SI trust claims** (mapping: see [EAR trust vector](#ear-trust-vector)) |
| EAR builder | hoisted out of `HpkeEarVerifier` into a shared module; HPKE output unchanged |
| T=1 client | written fresh for libattest (Apache-2.0, Siemens header); the ResearchProject probe is protocol reference only |
| CI | no simulator job; `make se05x-test` is a documented pre-merge step |
| Driver dev-dependency | `LinuxJedi/nxp-se050` fetched by commit SHA `af49819d1e09e25dfa438a8858f7ed89cd53944a` |

## File ownership (one owner per file; nobody else edits it)

| Track | Files |
|---|---|
| **SIM** | `docker/se05x-demo/sim/**`, `docker/se05x-demo/Dockerfile.se05xsim`, `LICENSES/GPL-3.0-or-later.txt`, `REUSE.toml` |
| **FMT** | `src/libattest/formats/se05x/**`, `src/libattest/formats/stmt_mappings.py`, `src/libattest/formats/media_types.py`, `tests/test_stmt_mappings.py`, `tests/test_se05x_formats.py` |
| **ATT** | `src/libattest/attester/se05x_client.py`, `tests/test_se05x_client.py` |
| **VER** | `src/libattest/verifier/ear.py` (new), `src/libattest/verifier/hpke_base.py`, `src/libattest/verifier/se05x.py`, `tests/test_se05x_verifier.py`, `tests/test_ear_builder.py` |
| **RA** | `src/libattest/ra/profile.py`, `src/libattest/ra/__init__.py`, `tests/test_se05x_profile.py` |
| **DEMO** | `docker/se05x-demo/{docker-compose.yml,Dockerfile.client,provision.py,se05x_demo.py,test_se05x_demo.py,check_key_per_start.py,README.md}`, `Makefile`, `ruff.toml`, `tests/data/se05x/**`, `tests/test_se05x_golden.py` |
| **PLAN** (before the tracks) | `docs/plans/2026-09-23-se05x-*.md`, `CONTEXT.md` (glossary: Attested Read, and the Evidence entry) |

Existing files other than those listed are not touched. The working tree carries the user's
uncommitted work: make additive hunks only, never reformat a whole existing file, never commit.

## Interfaces

### FMT: `libattest.formats.se05x`

- `structures.py`
  - OIDs (placeholder arc, defined only here): `id_se05x_attest_request` `1.3.6.1.4.1.99999.7.1`,
    `id_se05x_attest_response` `…7.2`, `id_se05x_attest_statement` `…7.3`.
  - `class Se05xAttestEvidence(univ.Sequence)`: `commandApdu`, `responseBody`, both `OCTET STRING`.
  - `prepare_se05x_attest_evidence(command_apdu: bytes, response_body: bytes) -> Se05xAttestEvidence`
  - `encode_se05x_attest_evidence(...) -> bytes` and
    `decode_se05x_attest_evidence(der: bytes) -> Se05xAttestEvidence` (strict: no trailing bytes).
- `apdu.py` (stdlib only): the byte-level SE05x attestation codec.
  - Constants: `INS_READ_ATTEST = 0x22`, the tags `41`-`47`, `4F`, `52`, `ATTEST_KEY_ID = 0xF0000012`,
    `CERT_OBJECT_ID = 0xF0000013`, `UNIQUE_ID_OBJECT_ID = 0x7FFF0206`, `ALGO_ECDSA_SHA256 = 0x21`,
    `FRESHNESS_LEN = 16`, `ORIGIN_INTERNAL = 0x02`, `TYPE_EC_KEY_PAIR_NIST_P256 = 0x29`,
    `P256_KEY_SIZE = 0x0020`, and the policy bits needed by the client (`POLICY_ALLOW_READ`,
    `POLICY_ALLOW_SIGN`, `POLICY_ALLOW_VERIFY`, `POLICY_ALLOW_DELETE`, `POLICY_ALLOW_ATTESTATION`).
  - TLV encode/decode (short, `81`, `82` length forms).
  - `build_attested_read(object_id: int, freshness: bytes, *, attest_key_id=ATTEST_KEY_ID, algo=ALGO_ECDSA_SHA256) -> bytes`:
    the full wire APDU with extended Lc and extended Le `00 00`.
  - `recorded_command(apdu: bytes) -> bytes`: the wire APDU without its Le, i.e. what the SE hashes.
  - `parse_attested_read_command(cmd: bytes) -> AttestedReadCommand` (frozen dataclass:
    `object_id`, `attest_key_id`, `algo`, `freshness`): strict, exactly `41 45 46 47`, Lc equals the
    data length, no Le.
  - `parse_attested_read_response(body: bytes) -> AttestedReadResponse` (frozen dataclass: `value`
    or `None`, `chip_id`, `attributes`, `object_size`, `timestamp`, `signature`): strict order
    `[41] 42 43 44 4F 52`, no trailing bytes, no status word.
  - `signed_message(command: bytes, response: AttestedReadResponse) -> bytes`:
    `SHA-256(command) || TLVs re-encoded with 82 hh ll` (TLV `41` only when present).
  - `parse_attributes(attributes: bytes) -> ObjectAttributes` (frozen dataclass: `object_id`,
    `type_code`, `policies` as `(auth_object_id, ar_header)` tuples, `origin`); ignores bytes after
    the origin; must accept an attribute block with no policy entries.
- Registration: statement name `se05x-attest`, request name `se05x-attest-request`, response
  name `se05x-attest-response` in `stmt_mappings.py`; `ATTESTATION_STATEMENT_STRUCTURES` maps the
  statement OID to `Se05xAttestEvidence`; no reqInfo/respInfo structures.
- `formats/media_types.py`: `SE05X_ATTESTATION_MEDIA_TYPE = "application/vnd.nxp.se05x-attestation+der"`
  (documented placeholder, like `application/vnd.tcg.platform`), added to `__all__`.

### ATT: `libattest.attester.se05x_client`

- `T1Transport(host, port, timeout=5.0)`: T=1 over TCP as the simulator's `tcp_server` speaks it
  (3-byte header, `LEN + 2` bytes, CRC-16/X.25 low byte first, NAD `0x5A`/`0xA5`), soft reset,
  chaining in both directions, `transceive(apdu) -> (data, sw)`.
- `Se05xClient(host, port)`, a context manager, with: `select()`, `read_object(object_id)`,
  `write_binary(object_id, data)` (extended Lc; data up to the simulator's limit),
  `generate_ec_key(object_id, *, policy: int | None)` (P-256), `delete_object(object_id)`,
  `get_timestamp()`, `attested_read(object_id, freshness) -> tuple[bytes, bytes]` returning
  `(recorded_command, response_body)`, and `sign_digest(key_id, digest) -> bytes` (DER ECDSA,
  SHA-256 prehash; for CSR proof-of-possession later). Non-`9000` status words raise
  `Se05xError(sw)`.
- `Se05xAttestProvider(client, *, key_id, cert_chain_pem)`: `generate_evidence(nonce) -> AttestResult`
  with `oid = get_oid_for_stmt_name("se05x-attest")`, DER `Se05xAttestEvidence`,
  `SE05X_ATTESTATION_MEDIA_TYPE`, and the certificate chain. A nonce that is not exactly 16 bytes
  raises `ValueError` naming `NonceStore(nonce_bytes=16)`.
- Bundles use `prepare_asn1_attestation_statement` (the statement is a SEQUENCE, not an
  OCTET STRING).

### VER: `libattest.verifier.ear` and `libattest.verifier.se05x`

- `verifier/ear.py`: `ear_token_to_veraison_claims` (moved from `hpke_base.py`, which keeps a
  re-export) and `build_ear_jwt(*, signing_key, verifier_developer, scheme_name, nonce: bytes, status: str, trust_vector: dict[str, int], policy_id: str | None = None) -> str`.
  `HpkeEarVerifier` calls it with its current vectors, so its EARs are byte-for-byte unchanged apart
  from `iat`.
- `verifier/se05x.py`: `Se05xAttestVerifier(*, roots: list[x509.Certificate], policy_id: str, ear_signing_key=None, verifier_developer=DEFAULT_VERIFIER_DEVELOPER)`
  implementing the RA port natively (`accepts`, `media_type`, `verifier_id`,
  `ear_verification_pem()`, `appraise(request: AppraisalRequest) -> VerifyResult`). No
  `AttestationVerifier` subclass. Checks, cheapest first: media type and 16-byte nonce; strict
  decode; command shape; attestation key id; algorithm `0x21`; `TAG_7 == nonce`
  (`hmac.compare_digest`); strict response; `TAG_1` present and a 65-byte P-256 point; attribute
  object id equals the command's; type `0x29`, origin `0x02`, size `0020`; certificate chain from
  `request.endorsements` to `roots` (`verifier.trust.validate_ek_chain`), any certificate parse
  error included; the leaf is an end-entity signing certificate (not a CA; keyUsage, if present,
  has `digitalSignature`); ECDSA over `signed_message` with the leaf key; if
  `request.subject_key` is given, it is the same key as `TAG_1` (compared as keys, so any valid
  SPKI encoding matches). Affirming result: `VerifyResult.affirming(<EAR JWT>)`; any failure:
  `VerifyResult.contraindicated(<reason>)`.

### RA: `libattest.ra.se05x_profile`

`se05x_profile(*, verifier, binds_subject_key=True, reference_handler=None, ear_oid=None) -> AttestationProfile`
with request, response and statement OIDs from the names above, no reqInfo/respInfo,
`media_type`, `verifier_id` and `ear_anchor` read from the verifier (as `hpke_profile` does).
Exported from `libattest.ra`. No `PROFILE_BUILDERS` entry yet: that table builds remote-URL
profiles, and an SE05x remote verifier service does not exist.

**For the CMP example later:** the MockCA registers `se05x_profile(verifier=Se05xAttestVerifier(...))`
in its `ProfileRegistry`, uses `NonceStore(nonce_bytes=16)` for that deployment, and must pass the
CSR's SubjectPublicKeyInfo to `engine.verify_bundle(..., pubkey=...)`. Today it calls
`verify_bundle(bundle_der, tx_id)` without it (`mock_ca/rats_handler.py`), which the engine
answers with "key attestation requires the to-be-certified SubjectPublicKeyInfo".

### SIM: the patched simulator

- `sim/0001-*.patch`, `sim/0002-*.patch`: PR #19, vendored unchanged (SHA-256 in `sim/README.md`).
- `sim/0003-se05x-attestation.patch`: the reviewed combined patch
  (`<artifacts>/synthesis/combined-attestation.patch`) plus: random key per start
  (`SE050_SIM_ATTEST_SEED` opt-in); the review's fix tests moved into `SE050Sim/se050-sim/tests/`;
  the stale 3.1.1 test renamed; the timestamp's one-second start wait done once at start-up, outside
  the store lock; a Siemens copyright line on the new file.
- `sim/Cargo.lock`: the pinned lockfile; builds use `--locked`.
- `Dockerfile.se05xsim`: digest-pinned `rust:1.98.1-bookworm` builder and `debian:bookworm-slim`
  runtime; fetch `ee28091`, `git am` 0001-0002, `git apply` 0003, driver by SHA; a `test` stage
  running the crate's full test suite; non-root runtime user; `tcp_server` on port 8050.

### DEMO: `docker/se05x-demo`

Compose services: `se05xsim` (no host port, `init: true`, TCP health check), `provision`
(one-shot), `test` and `demo` on one client image (`python:3.13-slim` pinned by digest, `git`
installed, libattest's `[project].dependencies` plus the `testing` extra). The demo runs the whole
RA flow in-process: engine with `NonceStore(nonce_bytes=16)`, `se05x_profile`, an
`EarAcceptancePolicy`; issue nonce, generate the SE key, build the bundle, `verify_bundle` with the
SE key's SPKI as `pubkey`, show the accepted EAR, then show a replayed bundle being refused.
Makefile: `se05x-build`, `se05x-test`, `se05x-demo`, `se05x-down`, with help lines.

## EAR trust vector

Grounded in draft-ietf-rats-ar4si-10 and draft-ietf-rats-ear-04 (the latest revisions on
2026-09-23; neither is an RFC), mapped from the verifier's checks, and reviewed from three angles
(spec fidelity, honesty about the demo, libattest consistency). Evidence: `<artifacts>/ar4si/`.

| Case | EAR |
|---|---|
| All checks pass (demo) | submod `SE05X`, `ear.status` = `affirming`, trust vector `{"instance-identity": 2}` |
| Any check fails | **no EAR**: `VerifyResult.contraindicated(<reason>)`, as the existing in-process verifiers do; the engine passes a failed verdict through without EAR appraisal |

- **instance-identity = 2** (AR4SI -10 §2.3.4): "The Attesting Environment is recognized, and the
  associated instance of the Attester is not known to be compromised." It rests on the Evidence
  signature by the attestation key, that key's certificate chaining to the configured root, and the
  fresh RA nonce. "Recognized" means "holds the key of an attestation certificate issued under the
  configured root"; the published policy says so. It holds only with a random attestation key per
  start: a simulator started with `SE050_SIM_ATTEST_SEED` makes the claim false. The verifier
  requires an end-entity signing leaf; that the roots certify only SE05x attestation keys is a
  deployment requirement, because the leaf, not `TAG_5`, fixes the signer (review, 2026-09-24).
- **hardware: omitted** while the root is the demo root. `2` ("passed its hardware and/or firmware
  verifications needed to demonstrate that these are genuine/supported") belongs only to a
  deployment whose roots are NXP's attestation CA **and** that has a revocation input. Not
  implemented.
- **The other six claims are omitted** (configuration, executables, file-system, runtime-opaque,
  storage-opaque, sourced-data): the Evidence says nothing about them. AR4SI §3.1: "A missing entry
  means that the verifier makes no claim about this specific appraisal facet".
- **Key provenance is a gate, not a claim.** Origin INTERNAL, type, size, object id, `TAG_1` and the
  subject-key binding must all pass for `affirming`; no AR4SI claim describes the provenance of one
  key.
- **Policy id:** a **required** `policy_id` constructor argument of `Se05xAttestVerifier` naming the
  trust-anchor class, e.g. `policy:SE05X/demo-sim-root` in the demo. No default, so a demo appraisal
  can never look like an NXP-rooted one, also inside an issued certificate's EAR extension.
- **Builder:** hoisted without a runtime guard. A guard on status versus vector would make
  `HpkeEarVerifier.issue_ear(nonce, "warning")` raise, because the legacy HPKE warning vector is all
  `99`. `build_ear_jwt` takes a `policy_id` that defaults to `policy:<submod>`, so the HPKE EARs stay
  identical.
- **If an EAR on failure is ever needed:** chain or certificate failure `97`, Evidence signature
  failure `99`, revocation (once it exists) `96`, `ear.status` = `contraindicated` (EAR -04 §3.1: the
  status is "no higher trust than the tier corresponding to the worst trustworthiness claim").
- **Identity evidence gap:** AR4SI §2.2 wants Identity Evidence in the result so its signature can be
  tied to the appraised Attesting Environment. The EAR carries none; in this background-check flow
  the RA is the challenger and the one-shot nonce ties the result to the exchange. The standard fix is
  EAR PR #77 (`ear_verified_attester_key`, open); not implemented.
- **Test:** one test asserts the exact affirming submods
  `{"SE05X": {"ear.status": "affirming", "ear.trustworthiness-vector": {"instance-identity": 2}, "ear.appraisal-policy-id": "policy:SE05X/demo-sim-root"}}`
  and that `EarAcceptancePolicy` accepts the EAR with the verifier's pinned key.
- **README caveats:** the demo root is not NXP's; the SE is a simulator whose key lives in a host
  process; omitted claims mean "no claim", not "good"; the chip id is signed but not bound to the
  certificate; the EAR uses Veraison's dotted-key wire format (profile
  `tag:github.com,2023:veraison/ear`) with AR4SI -10 labels.

## Quality gates

`make unit_tests`; `uv run ruff check` and `ruff format --check` on the new and touched files;
`uv run pyright` on the new modules; `make check-oids` with 0 violations; `reuse lint`;
`make se05x-test` (Docker) passing; the simulator image's `test` stage passing.
