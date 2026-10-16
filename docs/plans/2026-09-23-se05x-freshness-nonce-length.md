<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# SE05x attestation: the RA nonce is the 16-byte freshness value

Status: decided 2026-09-23 in the grilling session on the SE05x simulator demo; implemented
2026-09-24 (see [`2026-09-23-se05x-attestation-implementation.md`](2026-09-23-se05x-attestation-implementation.md)).
This decision **supersedes** the exploration's recommendation of a derived freshness
value ([R-SYN] §5.2 and decision D6): no `freshness()` derivation is added, and `TAG_7` carries
the RA nonce itself.

In this document, RA means the Registration Authority, which acts as the RFC 9334 Relying Party
(ADR-0004). It issues the freshness nonce.

## Decision

The RA issues a **16-byte nonce** for SE05x attestation. The Attester places that nonce
**unchanged** in the freshness field `TLV[TAG_7]` of the SE05x attested read. No hashing or other
transformation is applied.

- **RA.** The deployment that serves SE05x attesters uses `NonceStore(nonce_bytes=16)`. The RA
  knows the required length from its configuration, which the freshness draft allows as
  "out-of-band" knowledge ([I1] §8). No engine change is needed
  ([How libattest issues a 16-byte nonce today](#how-libattest-issues-a-16-byte-nonce-today)).
- **Attester.** Omit `NonceRequest.len`; it is optional ([I1] §3). If the received nonce is not
  exactly 16 bytes, fail closed with an error that names the cause, for example "SE05x attestation
  needs a 16-byte nonce; configure the RA with `NonceStore(nonce_bytes=16)`". Never pad or truncate
  the nonce.
- **Verifier.** Require `len(AppraisalRequest.nonce) == 16`. Read `TAG_7` out of the signed command
  APDU in the Evidence and compare it with `AppraisalRequest.nonce` using `hmac.compare_digest`.
  The Evidence is `Se05xAttestEvidence ::= SEQUENCE { commandApdu OCTET STRING, responseBody OCTET
  STRING }`: it carries **no separate nonce field** and no copy of the algorithm byte, which the
  verifier reads from the signed `TAG_6` (decided 2026-09-23). A verifier that compared against a nonce copied
  into the Evidence would accept replays, because the SE does not sign such a field ([R-E] §4b,
  [R-V4] V4). The comparison means something only because the SE's signature covers the whole
  command ([How the SE binds freshness](#how-the-se-binds-freshness)).

This keeps the SE05x path as simple as the TPM quote path, which also carries the RA nonce
unchanged and compares it byte for byte ([L7]).

## How the SE binds freshness

An SE05x attested read (`ReadObject` with the `INS_ATTEST` flag) is a request/response pair:

1. The host sends the request. It names the object to read, the attestation key, the signature
   algorithm, and a freshness value ([N2] §3.1 step 3, p. 7; the tag is `TLV[TAG_7]`, [N1] Table
   105, p. 66, and [C1]).
2. The SE answers with the object value, the chip id, the object attributes, the object size, a
   timestamp, and a signature ([N2] §3.1 step 4, p. 8).
3. From IoT applet 7.2.0 on ([N2] §3, p. 6), the signature covers **the hash of the full plain
   request command (without Le)** followed by the response fields ([N2] §3.1 step 4, p. 8).
4. The request command is sent to the verifying service together with the response
   ([N2] §3.1 step 5, p. 8). In libattest's planned Evidence it is the `commandApdu` field
   ([R-SYN] §3.2).

Because the request command contains `TAG_7`, whatever the host puts in `TAG_7` is covered by the
SE's signature. The verifier reads the freshness value back out of that command and checks it
against the nonce it issued.

Two different hashes came up during the exploration. Only NXP's is part of this design:

| Hash | Defined by | Part of this design? |
|---|---|---|
| The SE hashes the request command and signs it together with the response | NXP ([N2] §3.1 step 4, p. 8) | Yes. The chip does it; it is not optional. |
| `SHA-256("libattest-se05x-freshness-v1" \|\| nonce)[:16]`, to fit a longer RA nonce into 16 bytes | The exploration ([R-SYN] §5.2, D6) | **No.** With a 16-byte nonce it is not needed. See [Future option](#future-option-bind-the-exchange-context). |

The derivation hash existed only to fit a longer nonce into `TAG_7`'s 16 bytes.

## Why the freshness value must be 16 bytes

Every source that states or uses a length says 16 bytes, and none states or uses another:

| # | Source | Applet versions | What it says or does | Reference |
|---|---|---|---|---|
| 1 | NXP AN12413 Rev. 2.12, §3.2.7.2 "Reading with attestation" | 3.1.0, 3.1.1, 3.6.0 ([N1] §2.3, p. 4) | "Pass a 16-byte (random) freshness byte array." | [N1] p. 14 |
| 2 | NXP AN12413, ReadObject C-APDU | same | `TLV[TAG_7]`: "16-byte freshness random" | [N1] Table 105, p. 66 |
| 3 | NXP AN12413, I2CM_ExecuteCommandSet C-APDU (attested sensor reads) | same | `TLV[TAG_7]`: "16-byte freshness random" | [N1] §4.17.1, Table 247, p. 105 |
| 4 | NXP Plug & Trust, attested read of the ECKey session key | **7.2 and later** | declares `uint8_t random[16]` and passes it to `Se05x_API_ReadObject_W_Attst_V2`, the applet-7.2 call | [C2] |
| 5 | NXP Plug & Trust, applet-3.x attestation result | before 7.2 | freshness echo buffer fixed at `outrandom[16]` | [C3] |
| 6 | wolfSSL SE05x port ([PR 11377], merged 2026-09-15) | 7.2 and later | `SE050_ATTEST_RANDOM_SIZE 16U`; attest and verify both return `BAD_FUNC_ARG` for any other size | [C4], [C5], [C6], [C7] |
| 7 | The patched SE050 simulator used for the demo | 7.2 personalities | answers `6A80` (wrong data) unless `TAG_7` is exactly 16 bytes | [S1] |

**What this means for applet 7.2 and later, which the demo uses.** AN12413 Rev. 2.12, the only
public NXP document that fixes the length, covers applets 3.x ([N1] §2.3, p. 4). AN13254 describes
the "new attestation command format" of IoT applet 7.2.0 and later ([N2] §4, p. 10), but asks only
for "some random freshness data" and gives no length ([N2] §3.1 step 3, p. 7). The IoT applet APDU
specification for 7.x is AN12543, which NXP gates behind an account login ([N3]); it was not
consulted. For 7.2 the 16-byte length therefore rests on NXP's own middleware (row 4) and on
wolfSSL (row 6), both of which use exactly 16 bytes with the 7.2 command.

One source is silent: Plug & Trust's command builder copies whatever length the caller passes
into `TAG_7`, with no check on that length ([C1]). That is a missing host-side guard, not permission
from the chip. What real silicon does with a 32-byte `TAG_7` is undocumented and was not tested.

## Why the RA's default 32-byte nonce cannot be used unchanged

libattest's RA issues 32-byte nonces by default ([L1]). A 32-byte value does not fit the SE's
freshness field:

- The patched simulator refuses it with `6A80`. A 16-byte `TAG_7` returns `9000`; 15, 17 and 32
  bytes return `6A80` ([S1]; [R-S] §4 scenario S8 and §5.5; [E2]).
- wolfSSL refuses it on both the attesting and the verifying side ([C5], [C6], [C7]).
- NXP's own middleware uses 16 bytes with the applet-7.2 command ([C2]). For 7.2 chips, 32 bytes
  is **unspecified**, not proven wrong, and it is out of specification for applet 3.x ([N1]).

**The simulator branch.** The demo simulator is the unmerged upstream PR #19 branch plus our
attestation patch ([Why the simulator is built on PR #19](#why-the-simulator-is-built-on-pr-19)).
Every option in this report depends on that branch equally. Accepting 32 bytes would be one more
one-line change on it ([S1]). That change was rejected because it would teach libattest a protocol
that NXP's middleware and wolfSSL do not use, and wolfSSL would refuse those reads. The independent
conformance check used during the exploration ([R-K] §4) would then no longer cover them.

## Why the simulator is built on PR #19

The demo simulator is wolfSSL's SE050Sim with two layers on top: the unmerged upstream PR #19
([PR 19], head `11fc044`) and our attestation patch ([S1]). PR #19 matters because an SE05x
attested read signs properties of the object that only PR #19 models. The SE signs the object's
attributes into every attested read ([N2] §3.1 step 4, p. 8), and those attributes include the
object's policy and its origin.

| What an attested read needs | Upstream `main` (`ee28091`) | PR #19 (`11fc044`) |
|---|---|---|
| The object attributes in the applet-7.2 layout | no attribute command, no layout | `ReadObjectAttributes` (`P2_ATTRIBUTES = 0x3B`, [P1]; `handle_read_attributes`, [P2]). Our patch reuses this encoder for the signed attributes field. |
| The object's policy | a policy is kept only for HMAC keys ([U2], [U3]); WriteBinary skips it ([U4]); one policy bit is defined ([U1]) | per-object `ObjectMetadata { policy, origin }` ([P3]), stored by `set_creation_metadata` ([P4]), parsed by `creation_policy` ([P5]) |
| The object's origin. The demo's claim "this key was generated inside the SE" is the origin value INTERNAL | not recorded anywhere: no occurrence of `origin` in `src/` | recorded when a key is created ([P6]) |
| Policy enforcement, default-deny once a policy is attached | none | `policy_allows` ([P7]), applied by PR #19 to read, write and delete |

What PR #19 does **not** do, and our patch adds:

- the attested read itself and GetTimestamp;
- the provisioned attestation key and the chip id object;
- the policy checks on signing (`ALLOW_SIGN`) and on ECDH (`ALLOW_KA`) that keep the attestation
  key usable for attestation only. These checks call PR #19's `policy_allows`.

Our patch calls PR #19's functions directly (counted over the added lines of [S1]):

| PR #19 function | Calls in our patch |
|---|---|
| `set_creation_metadata` | 5 |
| `policy_allows` | 4 |
| `metadata` | 3 |
| `creation_policy` | 3 |

Without PR #19, our patch would have to re-create the metadata storage, the attribute encoding and
the policy mechanism itself, and it would drift from where upstream is heading. PR #19 is by the
SE050Sim maintainer, who also wrote wolfSSL's host-side attestation API ([PR 11377]); the PR #19
description names that PR as related.

**The risk, and how the build handles it.** PR #19 is not merged and may change. The build
therefore never fetches the fork. It takes upstream `main` at `ee28091` and applies PR #19 as two
vendored patch files, which gives a source tree identical to the PR head ([R-SYN] §2.3 and X9).
Those two files and our patch live in libattest under `docker/se05x-demo/sim/`, marked
GPL-3.0-or-later in `REUSE.toml` (decided 2026-09-23). If PR #19 lands in a changed form, our
patch is re-mapped onto it ([R-SYN] §7.1).

## What the simulator attestation patch does

The patch ([S1]) teaches the simulator NXP's applet-7.2 attestation and closes the policy gaps
that attestation depends on. Measured against the PR #19 tree it changes 14 files, adding 929
lines and removing 24. Most of it is the new `handlers/attest.rs` (425 lines, about half of them
unit tests) and the new end-to-end test file `tests/attestation.rs`. Line numbers below refer to
the patched tree under `SE050Sim/se050-sim/src/`.

1. **Attested read.** A read with the attestation bit set (INS `0x22`) is routed to a new handler
   before the instruction mask would turn it into a plain read (`dispatch.rs:54`).
   - The request must match NXP's format exactly: known tags only, each at most once, a 16-byte
     freshness value (`handlers/attest.rs:137`), and one of the hash algorithms SHA-224, SHA-256,
     SHA-384 or SHA-512. Otherwise the answer is `6A80`.
   - The named attestation key must be a P-256 key pair whose policy explicitly allows attestation
     and does not forbid everything; otherwise the answer is `6982` (`handlers/attest.rs:157-165`),
     the only status word NXP specifies for this case ([N1] §3.2.7.2).
   - The response carries the object's public value, the chip id, the object attributes, the
     object size, a timestamp and a DER-encoded ECDSA signature. The signature covers the hash of
     the command without Le, rebuilt with an extended Lc (`handlers/attest.rs:195`), followed by
     the response fields (`handlers/attest.rs:216`).
   - If the object's policy forbids reading, its value is left out; the attributes are still
     signed.
2. **GetTimestamp** (`80 04 00 3D`), answered on every personality (`dispatch.rs:210`). The
   12-byte timestamp is shared by all connections: 4 bytes of whole seconds, fixed when the server
   starts, then 8 bytes of 100 ms ticks that never repeat (`object_store/mod.rs:219` and `:228`).
   The server waits for the next whole second once at start-up, before it accepts connections
   (`bin/tcp_server.rs:136`), so the persistent part grows even across a quick restart.
3. **Two objects provisioned at start-up** (`bin/tcp_server.rs:119-135`, `handlers/attest.rs:64`):
   the attestation key at `0xF0000012` (P-256, readable and usable for attestation only, origin
   "provisioned") and an 18-byte chip id at `0x7FFF0206` (readable only). Both come from 32 random
   bytes drawn from the operating system at every start. Setting `SE050_SIM_ATTEST_SEED` makes them
   deterministic for reproducible tests, and the log says which of the two happened.
4. **Protection of those objects.** Delete-all keeps them (`object_store/mod.rs:200`). Their
   policies grant neither writing nor deletion, and a simulator shortcut that overwrote objects
   during ECDH can no longer replace them (`handlers/ec.rs:838`).
5. **More policy enforcement, not only for attestation.** Once a policy is attached, signing needs
   the sign permission (`handlers/ec.rs:509`) and ECDH needs the key-agreement permission
   (`handlers/ec.rs:762`). This is what keeps the attestation key from signing host-chosen data
   or acting as an ECDH oracle.
6. **Origin tracking fix.** PR #19 recorded an object's origin only on first creation ([P6]), so a
   key the host imported over a generated one still claimed "generated inside the SE". The origin
   now follows the latest key value while the policy stays fixed (`object_store/mod.rs:155`).
   This was the critical defect the exploration's review found ([R-SYN] D3).
7. **Plumbing.** The attribute encoder is split out so the attested read and ReadObjectAttributes
   produce identical bytes. The plain-read and hash helpers become crate-visible so the handler
   reuses them. A few tag and instruction constants are added.

**Tests.** Six unit tests cover the signature check, the policy refusals, timestamp ordering, the
protection of the provisioned objects, the 3.1.1 behaviour and reads without a value
(`handlers/attest.rs:307-424`). Seven end-to-end tests in `tests/attestation.rs` cover the review's
fixes, the routing of every instruction with the attestation bit, the signed command over plain,
chained, short-Lc and Platform SCP03 transports, the freshness length, and a timestamp that keeps
growing across a quick restart. The image's test stage runs all 141 crate tests.

**Not covered on purpose:** the legacy 3.x response format (the 3.1.1 personality refuses attested
reads with `6985`; it answers GetTimestamp), RSA and EdDSA attestation keys, attested attribute
reads, and attested sensor reads through the chip's I2C controller.

**Changed during implementation, compared with the reviewed exploration patch:** the random
attestation key per start (decision D4); the review's fix tests moved into the crate; a Siemens
copyright line on the new handler (the patch stays private and is not offered upstream); and the one-second
timestamp wait moved from the shared store lock to start-up.

## Why hashing was recommended first

The exploration recommended the derived value first ([R-SYN] §5.2, D6), for these reasons:

1. The nonce size is set per `NonceStore`, not per attestation profile ([L2]).
2. The engine does not honour `NonceRequest.len`: asking for 64 bytes still yields the store's size
   (row 4 of the table below).
3. The engine's `build_nonce_response` refuses `len=16` unless `min_nonce_length` is lowered
   (row 2 below).
4. An RA left at its default silently issues 32 bytes (row 5 below).

The Attester's fail-closed length check turns that misconfiguration into a clear error instead of a
silent failure, and the demo runs its own RA. That is why the 16-byte nonce is acceptable here and
keeps the first version simple: the value in `TAG_7` is the nonce itself, easy to read in logs, with
no derivation rule.

## Options considered

| Option | Simulator change | libattest change | Works with NXP middleware and wolfSSL |
|---|---|---|---|
| **Issue a 16-byte nonce and send it unchanged (chosen)** | none | none in the engine; a 16-byte `NonceStore` for the SE05x deployment | yes |
| Derive 16 bytes from the 32-byte nonce by hashing | none | one line in the attester, one in the verifier | yes |
| Let the simulator accept 32 bytes | one line | none | no |

## How libattest issues a 16-byte nonce today

No engine change is needed. The size of every issued nonce comes from the nonce store
(`self._nonce_bytes`, [L2]; `os.urandom(self._nonce_bytes)`, [L3]).

`RemoteAttestationEngine.build_nonce_response` treats a requested length only as a lower-bound
check against `min_nonce_length`, which defaults to 32 ([L4], [L6]). Its docstring says the
requested length "does not resize" the nonce ([L5]).

Verified by execution against the working tree ([E1]):

| # | Case | Result |
|---|---|---|
| 1 | Engine with `NonceStore(nonce_bytes=16)`, no `len` requested | 16-byte nonce |
| 2 | Same engine, `len=16` requested, default `min_nonce_length=32` | refused: `BadNonceRequest` |
| 3 | Same engine, `len=16` requested, `min_nonce_length=16` | 16-byte nonce |
| 4 | Same engine, `len=64` requested | still 16 bytes; the store size wins |
| 5 | Default engine | 32-byte nonce |

Rows 2 to 4 describe the API of `build_nonce_response`. No request handler in `src/` decodes
`NonceRequest.len` and passes it on today; only a unit test calls `build_nonce_response` with a
requested length ([R-RC-L] (e)). That is why the Attester omits `len` (row 1). If a later request
handler forwards `len`, it must also pass `min_nonce_length=16` for SE05x (row 3).

## Conformance with the standards

- **Nonce length.** The freshness draft allows 8 to 64 bytes in `NonceRequest.len` ([I1] §3, and
  the ASN.1 `len INTEGER (8..64)` in §3.1). It states that "the length of the nonce depends on the
  remote attestation technology in use" and that "nonces of incorrect length may cause the remote
  attestation protocol to fail" ([I1] §8). 16 bytes is in range and is what this technology needs.
- **How the RA learns the length.** The draft names two ways: "either out-of-band or through the
  len field" ([I1] §8). libattest uses the first: the store configuration.
- **Entropy.** The draft requires "at least 64 bits of entropy" ([I1] §8). EAT has the same entropy
  floor, and in CBOR its nonce is a byte string of 8 to 64 bytes (in JSON, a text string of 8 to
  88 bytes) ([I2] §4.1). A random 16-byte nonce carries 128 bits.
- **Uniqueness.** The draft requires a nonce that is "unique and MUST NOT be reused" ([I1] §8).
  That also satisfies AN13254's rule that the freshness of consecutive attestations "MUST be
  different" ([N2] §3.1 step 6, p. 8).
- **Timestamp continuity.** The same AN13254 step also says that timestamps of consecutive
  attestations "MUST be consecutive". That check is not implemented. The RA nonce is single-use
  (`ReplayError`, [L11]), so the check would add no replay protection ([R-V4] V7).
- **No transformation.** The draft says the end entity "MUST use the received nonce if the remote
  attestation technology used supports the requested length" ([I1] §8). Sending the 16-byte nonce
  unchanged is exactly that.
- **Architecture.** This is nonce-based freshness in the sense of RATS ([I3] §10.2).

## Limitations

- **The nonce size is per store, not per profile.** A single RA serving both SE05x and TPM
  attesters from one `NonceStore` would issue 16-byte nonces to the TPM path too. That is still
  secure (128 bits, and TPM quotes carry the nonce unchanged, [R-RC-L] (b)), but it changes
  existing behaviour. It would also be too short for technologies that need 32 bytes or more, such
  as PSA, which supports 32, 48 and 64 bytes ([I1] §8). A per-profile nonce size in the engine is
  the fix if such a deployment appears. The demo runs its own RA and does not need it.
- **The engine does not honour `NonceRequest.len`** (row 4). The draft says that if a length was
  requested, the RA "SHOULD provide a nonce of that size" ([I1] §3). This is a general libattest
  gap, independent of SE05x.
- **Side finding in the external MockCA.** Its `validate_nonce_request` calls `len()` on the
  decoded `NonceRequest.len`, which is an ASN.1 integer, so it raises `TypeError` whenever its
  `min_nonce_length` knob is set and `len` is present ([M1]). The knob defaults to `None`
  ([M2]), so the path is dormant today.
- **Demo-grade freshness.** The binding is only as strong as the attestation key's protection
  ([R-V4] V6):
  - In the simulator, the attestation private key lives in a process on the Docker host.
  - The simulator draws a random attestation key at every start (decision D4, implemented). A
    simulator started with `SE050_SIM_ATTEST_SEED` set uses a key that anyone who knows the seed
    can derive, so such a run is for reproducible tests only ([R-S] §2 and §3; [R-SYN] D4).
  - The demo root CA private key must stay outside the Attester container, in the one-shot
    provisioning container ([R-SYN] §2.2, §5.2).

  The demo shows the protocol, not the security of a real secure element.

## Consequences for the exploration artifacts

- The spike's `live_vector.json` and the reference verifier `wire/ref_verify.py` use the labelled
  derivation over a 32-byte nonce ([R-SYN] §3.7 and D6). Before either serves as a golden vector,
  recapture it with a 16-byte RA nonce and change the verifier to compare `TAG_7 == nonce`.
- The planned `freshness(nonce)` function in `formats/se05x/apdu.py` ([R-SYN] §4.1) is dropped.
  The verifier compares `TAG_7` with the nonce directly.

## Future option: bind the exchange context

Modern protocols bind the context of an exchange, not only a random value, into the values they
derive or sign:

- TLS 1.3 exporters take a label and a context value ([I4] §7.5).
- The `tls-exporter` channel binding builds on them ([I5] §2).
- HPKE takes an application-supplied `info` value ([I6] §5.1).
- COSE authenticates externally supplied data ([I7] §4.3).
- libattest already threads `hpke_info` and `external_aad` through its HPKE transports ([L8], [L9]).

The SE05x freshness field can carry such a binding later without any change on the SE side. Only
the 16 bytes the Attester puts in `TAG_7` change:

```
freshness = SHA-256( encode(label, context, nonce) )[0:16]
label     = "libattest-se05x-freshness-v1"      (separates this statement type's values)
context   = values both Attester and Verifier know, e.g. the statement type OID,
            the attestation key id, or a transaction identifier
encode    = an unambiguous encoding, e.g. a DER SEQUENCE or length-prefixed fields,
            as TLS 1.3 (HKDF-Expand-Label) and HPKE (LabeledExtract/LabeledExpand) do
```

What this adds:

- The RA already issues a separate nonce per statement OID ([L12]). A label and context add defence
  in depth, and they bind values the nonce alone does not, such as the attestation key id or a
  transaction id. A value derived for one statement type is accepted by another only with
  negligible probability.
- Any nonce length from 8 to 64 bytes works, so the 16-byte store and the per-store limitation
  above go away.

What it costs:

- One line on each side.
- Both sides must agree on exactly which context values go in, and on their encoding. The verifier
  already receives the statement OID in `AppraisalRequest` ([L10]).

What the draft requires of such a transformation:

- It must be deterministic, preserve the minimum entropy, and give the Verifier enough information
  to reconstruct or validate the value ([I1] §9).
- If the statement type defines a deterministic transformation, the end entity must apply only
  that transformation, and only for the purpose that specification defines ([I1] §8).
- Because the draft also requires using the received nonce when the technology supports its
  length ([I1] §8), the SE05x statement type must say that the transformation applies to every
  nonce length, with no "unchanged if 16 bytes" branch ([R-V4] V22).

When to do it: before the SE05x statement type leaves the placeholder OID arc `1.3.6.1.4.1.99999`.
Changing the rule later changes the statement type's wire contract, so it would need a new
statement OID.

## Evidence

All exploration artifacts are preserved, with a `SHA256SUMS` file, in the artifacts folder:
`~/.claude/projects/-home-debian-PycharmProjects-libattest-ra-wt/ea415bc2-8b08-4949-8d24-9431fa54a9b9/se05x-spike-artifacts/`
(below: `<artifacts>`).

- [E1] `<artifacts>/nonce/easy_path_check.py` (SHA-256
  `52b831541b64cb43d45b220bb0ab533b747c9d5ddb70132343f1ba508c90bfe1`). Run from the repository
  root with `PYTHONDONTWRITEBYTECODE=1 uv run python3 <artifacts>/nonce/easy_path_check.py`. It prints
  the five rows of the engine table and `OK`. Rows 4 and 5 are printed, not asserted.
- [E2] `<artifacts>/reportcheck/code-links/nonce32_rerun.log`: `TAG_7 of 16 bytes -> SW 9000`,
  `TAG_7 of 32 bytes -> SW 6A80`, re-run against the combined-patch simulator image on 2026-09-23.
- The citations in this report were checked by five independent reviewers; their verdicts are in
  `<artifacts>/reportcheck/*/verdicts.md`.

Exploration reports (in `<artifacts>/reports/`):

- [R-SYN] `SYNTHESIS.md`: the overall decision document (§2.2 Compose layout, §3 wire format,
  §4.1 libattest change list, §5.2 the superseded nonce rule, §6 decisions D4 and D6).
- [R-E] `E-nonce-binding.md`: the nonce-binding analysis.
- [R-V4] `V4-nonce-verdicts.md`: its adversarial review (V4 carried-nonce replay, V6 key premise,
  V7 timestamp continuity, V22 one rule for every length).
- [R-S] `S-spike.md`: the simulator spike (§2 design and seed, §3 build log, §4 scenario S8 and
  §5.5 freshness lengths).
- [R-K] `K-conformance.md`: the independent wolfSSL and Plug & Trust conformance run (§4).
- [R-RC-L] `<artifacts>/reportcheck/libattest/verdicts.md`: libattest carrier and TPM-path checks,
  items (b) and (e).

## References

libattest line numbers refer to the working tree on branch `UpdateV8_1` (commit `55e24fd` plus
uncommitted and untracked changes) on 2026-09-23. `nonce.py` and `engine.py` are modified;
`ports.py`, `hpke_base.py` and ADR-0004 are untracked. Line numbers move when those files change.

### NXP documents

- [N1] NXP, *AN12413 SE050 APDU Specification*, Rev. 2.12, 24 March 2021.
  <https://www.nxp.com/docs/en/application-note/AN12413.pdf>
  (SHA-256 `e98a72e4215ba2886d777509f066ff620925ae65999d9c28cbcf24b7f2cf5622`).
  Cited: §2.3 "Applet" (supported applet versions 3.1.0, 3.1.1, 3.6.0), p. 4; §3.2.7.2, p. 14;
  ReadObject Table 105, p. 66; §4.17.1 Table 247, p. 105.
- [N2] NXP, *AN13254 Secure attestation with EdgeLock SE05x*, Rev. 1.1, 26 July 2023.
  <https://www.nxp.com/docs/en/application-note/AN13254.pdf>
  (SHA-256 `42d7268d1c07836e889d91e695a5627cb6d21344efef8423c3e065877b236199`).
  Cited: §3, p. 6 (scope: IoT applet 7.2.0 and later); §3.1 step 3, p. 7; §3.1 steps 4, 5 and 6,
  p. 8; §4, p. 10 ("new attestation command format").
- [N3] NXP, *AN12543 SE05x IoT Applet APDU Specification* (requires an NXP account login; not
  consulted). <https://www.nxp.com/webapp/Download?colCode=AN12543>

### Code

Plug & Trust is pinned at commit `1ddf8cf0cdf9d7f77e32d7e62b19b6a58d74f5fa`, titled "Release
v04.08.00" and the head of `master`; no git tag exists for that release. wolfSSL is pinned at
`master` commit `d95483fff72d6e987394b72edca433d4b580a0f4`, which contains [PR 11377]
(merge commit `25d8e9ee`); `se050_port.c` is unchanged since that merge.

- [C1] Plug & Trust, `Se05x_API_ReadObject_W_Attst_V2`: `TAG_7` set with the caller's length, no
  length check:
  <https://github.com/NXP/plug-and-trust/blob/1ddf8cf0cdf9d7f77e32d7e62b19b6a58d74f5fa/hostlib/hostLib/se05x_03_xx_xx/se05x_APDU_impl.h#L868>
- [C2] Plug & Trust, `nxECKey_ReadEckaPublicKey`: `uint8_t random[16]` and `randomLen = sizeof(random)`
  (L8315-L8316), passed to `Se05x_API_ReadObject_W_Attst_V2` under `SSS_HAVE_SE05X_VER_GTE_07_02`
  (L8350-L8357):
  <https://github.com/NXP/plug-and-trust/blob/1ddf8cf0cdf9d7f77e32d7e62b19b6a58d74f5fa/sss/src/se05x/fsl_sss_se05x_apis.c#L8315-L8357>
- [C3] Plug & Trust, `sss_se05x_attst_comp_data_t.outrandom[16]`, compiled only when
  `!SSS_HAVE_SE05X_VER_GTE_07_02`:
  <https://github.com/NXP/plug-and-trust/blob/1ddf8cf0cdf9d7f77e32d7e62b19b6a58d74f5fa/sss/inc/fsl_sss_se05x_types.h#L353>
- [C4] wolfSSL, `SE050_ATTEST_RANDOM_SIZE 16U`:
  <https://github.com/wolfSSL/wolfssl/blob/d95483fff72d6e987394b72edca433d4b580a0f4/wolfcrypt/src/port/nxp/se050_port.c#L1652>
- [C5] wolfSSL, `wc_se050_attest_object` returns `BAD_FUNC_ARG` for other sizes:
  <https://github.com/wolfSSL/wolfssl/blob/d95483fff72d6e987394b72edca433d4b580a0f4/wolfcrypt/src/port/nxp/se050_port.c#L1787-L1789>
- [C6] wolfSSL, `se050_verify_attestation_freshness` returns `BAD_FUNC_ARG` for other sizes:
  <https://github.com/wolfSSL/wolfssl/blob/d95483fff72d6e987394b72edca433d4b580a0f4/wolfcrypt/src/port/nxp/se050_port.c#L2109-L2111>
- [C7] wolfSSL, `wc_se050_verify_attestation` returns `BAD_FUNC_ARG` for other sizes:
  <https://github.com/wolfSSL/wolfssl/blob/d95483fff72d6e987394b72edca433d4b580a0f4/wolfcrypt/src/port/nxp/se050_port.c#L2228-L2235>
- [S1] SE050 simulator attestation patch (not published), applied on top of [PR 19]:
  `SE050Sim/se050-sim/src/handlers/attest.rs` lines 133-143 in the patched tree. Line 137 holds
  `if fresh.len() != 16`, line 142 `return ApduResponse::error(SW_WRONG_DATA);`. Patch file
  `docker/se05x-demo/sim/0003-se05x-attestation.patch` in this repository, SHA-256
  `9c3a3db6c16e1e088438a6948bdbd2209bca3002bce12b1ca49156ea987cf330`; it grew out of the reviewed
  exploration patch `<artifacts>/synthesis/combined-attestation.patch` (SHA-256
  `b50220f15568da062d8e8aeb4c42501b93c05ad4d2c382c37bbfea9081a0cc82`).
- [PR 19] wolfSSL/simulators PR #19, open, head `11fc0440b66cb7cce5f8ed55006ee427b9b45db6`:
  <https://github.com/wolfSSL/simulators/pull/19>
- [PR 11377] wolfSSL/wolfssl PR #11377, merged 2026-09-15: <https://github.com/wolfSSL/wolfssl/pull/11377>
- [M1] External MockCA, `/home/debian/IdeaProjects/cmp-test-suite-update-code.tpm20-wt` at
  `cdeea56f` plus uncommitted changes: `resources/remote_attestation_utils.py:56-59`
  (`len(nonce)` on the ASN.1 integer `nonce_request["len"]`).
- [M2] Same repository, `mock_ca/db_config_vars.py:189`: `min_nonce_length: Optional[int] = None`.

### SE050 simulator: upstream `main` versus PR #19

Upstream is pinned at `ee280919229cceb7a5504b5dd40af90d8c0731cb` (the last SE050Sim change is
`2bd95a8`), PR #19 at `11fc0440b66cb7cce5f8ed55006ee427b9b45db6`. Paths are relative to
`SE050Sim/se050-sim/src/`.

- [U1] `policy.rs:34`, upstream: the only policy bit defined, `POLICY_OBJ_ALLOW_READ`.
  <https://github.com/wolfSSL/simulators/blob/ee280919229cceb7a5504b5dd40af90d8c0731cb/SE050Sim/se050-sim/src/policy.rs#L34>
- [U2] `object_store/types.rs:150`, upstream: `policy: Option<u32>` exists only on the `HMACKey` variant.
  <https://github.com/wolfSSL/simulators/blob/ee280919229cceb7a5504b5dd40af90d8c0731cb/SE050Sim/se050-sim/src/object_store/types.rs#L150>
- [U3] `handlers/aes.rs:263-273`, upstream: the policy is parsed and stored for HMAC keys only.
  <https://github.com/wolfSSL/simulators/blob/ee280919229cceb7a5504b5dd40af90d8c0731cb/SE050Sim/se050-sim/src/handlers/aes.rs#L263-L273>
- [U4] `handlers/object_mgmt.rs:94`, upstream: `TAG_POLICY => {} // Skip policy` on WriteBinary.
  <https://github.com/wolfSSL/simulators/blob/ee280919229cceb7a5504b5dd40af90d8c0731cb/SE050Sim/se050-sim/src/handlers/object_mgmt.rs#L94>
- [P1] `apdu.rs:223`, PR #19: `pub const P2_ATTRIBUTES: u8 = 0x3B;`
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/apdu.rs#L223>
- [P2] `handlers/object_mgmt.rs:54` (routing) and `:420` (`fn handle_read_attributes`), PR #19.
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/handlers/object_mgmt.rs#L420>
- [P3] `object_store/types.rs:24-35`, PR #19: `struct ObjectMetadata { policy, origin }`.
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/object_store/types.rs#L24-L35>
- [P4] `object_store/mod.rs:138`, PR #19: `pub fn set_creation_metadata`.
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/object_store/mod.rs#L138>
- [P5] `policy.rs:41`, PR #19: `pub fn creation_policy`.
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/policy.rs#L41>
- [P6] `handlers/ec.rs:144-149`, PR #19: after a successful WriteECKey, origin 2 (generated) or 1
  (imported) is recorded, but only when the object did not exist before. That condition is the
  "origin freeze" defect the exploration's review found; our patch fixes it ([R-SYN] D3).
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/handlers/ec.rs#L144-L149>
- [P7] `object_store/mod.rs:154-163`, PR #19: `policy_allows`, "Once a policy is attached, an omitted
  permission is a denial."
  <https://github.com/LinuxJedi/simulators/blob/11fc0440b66cb7cce5f8ed55006ee427b9b45db6/SE050Sim/se050-sim/src/object_store/mod.rs#L154-L163>

### libattest

- [L1] `src/libattest/ra/nonce.py:40`: `DEFAULT_NONCE_BYTES = 32`
- [L2] `src/libattest/ra/nonce.py:132,140`: the `nonce_bytes` parameter and `self._nonce_bytes`
- [L3] `src/libattest/ra/nonce.py:199`: `nonce=os.urandom(self._nonce_bytes)`
- [L4] `src/libattest/ra/engine.py:262-263`: `requested_len`, `min_nonce_length: int | None = 32`
- [L5] `src/libattest/ra/engine.py:289-293`: `requested_len` is validated only and "does not resize" the nonce
- [L6] `src/libattest/ra/engine.py:314-317`: the minimum-length check that raises `BadNonceRequest`
- [L7] `src/libattest/verifier/tpm/tpm_platform_verifier.py:150`: TPM quote nonce compared unchanged
- [L8] `src/libattest/verifier/hpke_base.py:120-121`: `hpke_info` and `external_aad` parameters
- [L9] `docs/adr/0004-ra-as-relying-party-and-verifier-port.md` lines 108-109: context binding in the HPKE transports
- [L10] `src/libattest/ra/ports.py:82-83`: `AppraisalRequest.nonce` and `AppraisalRequest.statement_oid`
- [L11] `src/libattest/ra/nonce.py:260-261`: a consumed nonce raises `ReplayError`
- [L12] `src/libattest/ra/nonce.py:194-205`: each nonce is filed under its statement OID

### IETF

- [I1] draft-ietf-lamps-attestation-freshness-08, *Requesting a Freshness Nonce for Attestation
  Evidence in Certificate Signing Requests*, 4 July 2026 (latest revision on 2026-09-23).
  <https://datatracker.ietf.org/doc/draft-ietf-lamps-attestation-freshness/08/>.
  Cited: §3 (`len` 8 to 64; "If a specific length was requested, the RA/CA SHOULD provide a nonce
  of that size"), §3.1 ASN.1 (`len INTEGER (8..64)`), §8 (entropy, uniqueness, technology-specific
  length, "either out-of-band or through the len field", "MUST use the received nonce", the
  transformation rule, PSA lengths), §9 (conditions for a nonce transformation).
- [I2] RFC 9711, *The Entity Attestation Token (EAT)*, §4.1 "eat_nonce (EAT Nonce) Claim": at least
  64 bits of entropy; 8 to 64 bytes in CBOR, 8 to 88 in JSON.
  <https://www.rfc-editor.org/rfc/rfc9711#section-4.1>
- [I3] RFC 9334, *Remote ATtestation procedureS (RATS) Architecture*, §10.2 "Implicit Timekeeping
  Using Nonces". <https://www.rfc-editor.org/rfc/rfc9334#section-10.2>
- [I4] RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*, §7.5 "Exporters" (label
  and context value). <https://www.rfc-editor.org/rfc/rfc8446#section-7.5>
- [I5] RFC 9266, *Channel Bindings for TLS 1.3*, §2 "The 'tls-exporter' Channel Binding Type".
  <https://www.rfc-editor.org/rfc/rfc9266#section-2>
- [I6] RFC 9180, *Hybrid Public Key Encryption*, §5.1 "Creating the Encryption Context" (`info`).
  <https://www.rfc-editor.org/rfc/rfc9180#section-5.1>
- [I7] RFC 9052, *CBOR Object Signing and Encryption (COSE): Structures and Process*, §4.3
  "Externally Supplied Data" (the `external_aad` field itself appears in §4.4).
  <https://www.rfc-editor.org/rfc/rfc9052#section-4.3>
