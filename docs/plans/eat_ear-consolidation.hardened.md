# Plan — consolidate CWT/JWT/JOSE/COSE token logic into `formats/eat_ear/`

## Hardening changelog
Applied adjudicator resolutions + three human conflict decisions (EATClaimsSet
keep-hardened, one-file-each layout, hard-move+doc-refresh public API) on top
of the original single-pass plan:
- **correctness-01 (BLOCKER)**: added explicit ALG/b64u/`InvalidSignature`/`__all__`
  de-collision step before merging into `cwt_jwt_utils.py`, with all 3 external
  call-sites that read `jose_hpke.ALG` enumerated and rewritten.
- **operability-01 (BLOCKER)**: replaced single-pass execution with a 4-commit
  sequence (3 mechanical + 1 semantic), each ending in green-suite + commit, so
  the tree is importable/revertable at every step.
- **contracts-01 (BLOCKER)**: added README.md/pyproject.toml/prototype-README doc
  refresh as mandatory edits (decision 3), no compatibility shim.
- **scope-01 (sequencing)**: mechanical relocation (commits 1-3) is now strictly
  separated from the `ClaimDef` registry + `EATClaimsSet` hardening (commit 4).
- **correctness-02/03, security-01 (MAJOR)**: `EATClaimsSet` hardening spec
  rewritten per human decision 1 — unions for `oemid`/`eat_nonce`, no 8-64 byte
  bound on generic byte-claims, `to_cwt_claims()` routes through
  `jwt_style_view_to_cwt_claim_set` (`jti_is_jwt_text=False`), `from_cwt()` dropped.
- **operability-02/03 (MAJOR)**: importer-edits table replaced with a complete
  per-file attribute-access rewrite list (~25 sites) and the verification grep
  rewritten to a bare-name scan that also catches `from ... import jose_hpke, jose_jws`.
- **contracts-02 (MAJOR)**: added `boot_seed`/`bootseed` dual-alias-for-one-release
  requirement + Risks entry.
- **operability-04 (MINOR)**: added `ruff.toml` path update as a mandatory step.
- **security-02 (MINOR)**: `eat_ear/__init__.py` no longer flat-exports unverified
  inspectors (`parse_ear_verdict`, `cose_cwt_to_jwt_view`).

## Goal
Make `src/libattest/formats/eat_ear/` the single home for the EAT/EAR token
representation + CWT/JWT/JOSE/COSE logic, for easier access. Keep the *better*
existing implementations, salvage the genuinely-new `EATClaimsSet` + claim
registry from the root scratch file `jwt_cwt_objects2.py`, and remove duplication.

## Principles (agreed with user)
- **One home, no duplication** (hard move) — delete old files, update every importer.
- **Keep the better code**: strict `cwt_jwt` conversion, draft-04 `EARToken`,
  `Base64UrlBytes`/`EATNonce`.
- **Fold in the new** `EATClaimsSet` + `ClaimDef` registry to raise quality
  (claim-label coverage 266→275, `is_bytes` flags, normative refs), hardened per
  the fixes below (unions, jti routing, no unverified `from_cwt`).
- **Leave alone**: `GeographicResultClaims`, `types.EarStatus`, and the `eareat_*`
  HPKE evidence-bridges (they stay in `formats/`, only their imports/attribute
  accesses get repointed).
- **No shim**: hard move of the public API, with README/pyproject/prototype docs
  refreshed in the same commit that flips imports.

## Baseline facts (verified by grep/reads)
- `src/libattest/ear.py` (392 lines): draft-ietf-rats-ear-04 model — `EARToken`,
  `EARAppraisal`, `TrustworthinessTier`, `Base64UrlBytes`, `EATNonce`, plus JWT
  helpers `parse_ear_verdict`/`verify_ear_jwt`/`ear_is_affirming`, `EAR_PROFILE`.
- `formats/cwt_jwt.py` (271 lines): strict, tested CWT-ClaimSet↔JWT-view conversion;
  `_CLAIM_NAME_BY_LABEL` built from python-cwt `CWT_CLAIM_NAMES` + RFC 9711 overrides
  (labels stop at 266); `_BYTE_CLAIM_NAMES` contains `boot_seed` (RFC name is `bootseed`).
- `formats/cwt_utils.py` (306 lines): `generate_es256_keypair`, `jwt_to_cwt_claims`,
  `convert_jwt_to_cwt`, `verified_jwt_to_signed_cwt`, `resign_cwt`. Imports
  `cwt_jwt.jwt_claims_to_cwt_claim_set`.
- `formats/jose_jws.py` defines module-level `ALG`, `b64u_encode`/`b64u_decode`,
  `InvalidSignature`. `formats/jose_hpke.py` (imports jose_jws) **also** defines its
  own module-level `ALG` (different value/semantics — HPKE suite id vs JWS alg) and
  its own `b64u_encode`/`b64u_decode`. `formats/cose_hpke.py` (imports cwt_utils) may
  also define overlapping names. These collide symbol-for-symbol once concatenated
  into one file — this is a correctness blocker, not a style nit (correctness-01).
- `jwt_cwt_objects2.py` (root scratch): `ClaimDef`+`CLAIMS` registry (labels 1-8,10,256-275),
  `EATClaimsSet` + `Location`/`DLOAEntry`/`SoftwareMeasurement`/`MeasurementResult`,
  `DebugStatus`/`IntendedUse` — genuinely new. Also `EAR`/`EARAppraisal`/`VerifierID`/
  `EARStatus`/`TrustTier`/`SignatureAlgorithm`/`HashAlgorithm`/`load`/`decode_cwt`/
  `cwt_to_jwt`/`jwt_to_cwt`/`DecodedToken` — all duplicate existing code.
- Nothing imports `jwt_cwt_objects2` (confirmed).
- 182 test functions in `tests/`.
- `libattest.ear` is documented public API (README.md:18) — a hard move requires a
  doc refresh, not silent breakage (contracts-01).

## Target structure
```
formats/eat_ear/
  __init__.py          # curated public API (re-exports); does NOT flat-export
                        # unverified inspectors (parse_ear_verdict, cose_cwt_to_jwt_view)
  cwt_jwt.py           # MERGE ear.py + formats/cwt_jwt.py + NEW EATClaimsSet/substructures/enums + ClaimDef registry
  cwt_jwt_utils.py     # MERGE cwt_utils.py + jose_jws.py + jose_hpke.py + cose_hpke.py
```
One merged file each (human decision 2) — do not switch to a split package.
Layering stays acyclic: `cwt_jwt_utils` → imports → `cwt_jwt` (never the reverse).

## Execution sequence — 4 revertable commits

The tree must be importable and the full suite green *after every commit*. Commits
1-3 are the pure mechanical hard-move (relocate the BETTER existing code verbatim,
plus the mandatory ALG/b64u de-collision). Commit 4 is the separately-reviewable
semantic work (`ClaimDef` registry + hardened `EATClaimsSet`) — never mixed into 1-3
(scope-01).

### Commit 1 — create `eat_ear/{cwt_jwt,cwt_jwt_utils}.py` alongside old files (no deletion)
- Create `formats/eat_ear/__init__.py`, `cwt_jwt.py`, `cwt_jwt_utils.py`.
- `cwt_jwt.py` content: `ear.py` + `formats/cwt_jwt.py` concatenated unchanged (no
  `EATClaimsSet`/registry yet — that's commit 4).
- `cwt_jwt_utils.py` content: `cwt_utils.py` + `jose_jws.py` + `jose_hpke.py` +
  `cose_hpke.py` concatenated, **with the mandatory pre-merge de-collision**:
  - rename `jose_jws.ALG` → `ES256_ALG`
  - rename `jose_hpke.ALG` → `HPKE0_ALG`
  - de-collide `b64u_encode`/`b64u_decode` (pick one canonical implementation,
    verify byte-for-byte equivalence with the other, delete the duplicate)
  - de-collide `InvalidSignature` (single exception class)
  - merge the two `__all__` lists, checking for name clashes
  - rewrite every internal reference to the old `ALG` names within this file
- Old files (`ear.py`, `formats/{cwt_jwt,cwt_utils,jose_jws,jose_hpke,cose_hpke}.py`)
  remain untouched; nothing imports the new `eat_ear` package yet.
- `python -m pytest -q` green (baseline behavior unchanged — new files are inert).
- **Commit.**

### Commit 2 — flip every importer + external ALG call-sites + docs to the new path
Full edit list (mechanical, exhaustive — see "Importer & attribute-rewrite edits"
below for the complete per-file breakdown, including the ~25 attribute-access
rewrites operability-02 flagged as undercounted in the original plan).
- Flip all `import`/`from` statements per the table below.
- Rewrite the 3 external call-sites that read `jose_hpke.ALG` directly to use
  `HPKE0_ALG` from `eat_ear.cwt_jwt_utils`: `eareat_hpke.py:103`,
  `verifier/eareat_cose_hpke/cose_hpke_verifier.py:158`,
  `verifier/eareat_hpke/eareat_hpke_verifier.py:125`.
- Rewrite the bare `jose_hpke.X`/`jose_jws.X`/`cwt_utils.X`/`cose_hpke.X` attribute
  accesses enumerated below to use the merged module.
- Doc refresh (contracts-01 / human decision 3, no shim): `README.md:18`,
  `pyproject.toml:22` comment, `prototypes/tpm_key_binding/README.md:29-30` — update
  to the new `libattest.formats.eat_ear` import path.
- `python -m pytest -q` green.
- **Commit.**

### Commit 3 — delete old files, update ruff.toml
- Delete: `jwt_cwt_objects2.py`, `src/libattest/ear.py`,
  `src/libattest/formats/{cwt_jwt,cwt_utils,jose_jws,jose_hpke,cose_hpke}.py`.
- Update `ruff.toml` per-file-ignores path from
  `src/libattest/formats/cwt_utils.py` to
  `src/libattest/formats/eat_ear/cwt_jwt_utils.py` (operability-04).
- Refresh `:mod:`/`:func:` docstring cross-references (accuracy sweep).
- `python -m pytest -q` green + `ruff check` clean (mandatory, not optional —
  operability-04).
- **Commit.**

### Commit 4 — semantic: `ClaimDef` registry + hardened `EATClaimsSet` (separate, reviewable)
See "`cwt_jwt.py` semantic addendum" below for full content. Ends in green suite +
new `demo()` self-checks + **commit**.

## `cwt_jwt.py` — contents & reconciliation (commits 1-3, mechanical)
Bring from `ear.py` unchanged: `parse_ear_verdict`, `verify_ear_jwt`, `ear_is_affirming`,
`Base64UrlBytes`, `EATNonce`, `TrustworthinessTier`, `EARAppraisal`, `EARToken`, `EAR_PROFILE`.

Bring from `formats/cwt_jwt.py` unchanged: `jwt_claims_to_cwt_claim_set`,
`jwt_style_view_to_cwt_claim_set`, `cwt_claim_set_to_jwt_view`, `cose_cwt_to_jwt_view` + helpers.

## `cwt_jwt.py` semantic addendum (commit 4 only)
Bring from `jwt_cwt_objects2.py` — KEEP & upgrade:
- `ClaimDef` + `CLAIMS` registry → new single source of truth. Derive
  `_CLAIM_NAME_BY_LABEL`/`_CLAIM_LABEL_BY_NAME`/`_BYTE_CLAIM_NAMES` from it; merge
  python-cwt `CWT_CLAIM_NAMES` as a fallback base (registry wins). Fixes: adds labels
  267–275 (swname…intuse); corrects `boot_seed`→`bootseed`.
- `EATClaimsSet` → **kept, hardened** (human decision 1 — this is the one missing
  model: typed EAT Evidence claims-set). Concretely:
  - `oemid: Union[int, Base64UrlBytes]` (was bytes-only).
  - `eat_nonce: Union[EATNonce, list[EATNonce]]` (was single `EATNonce`).
  - Do **not** apply the 8-64 byte length bound to the generic byte-claim path —
    that bound was over-fit to `nonce`/`ueid` and wrongly rejected other
    byte-typed claims (correctness-02).
  - `ueid`, `hwmodel`, `bootseed`, `jti` remain `Base64UrlBytes` subtypes.
  - `to_cwt_claims()` routes through `jwt_style_view_to_cwt_claim_set` semantics
    with `jti_is_jwt_text=False` (correctness-03) — no independent re-implementation
    of the JWT↔CWT claim mapping.
  - `from_cwt()` is **dropped**. Rationale (security-01): never decode unverified
    bytes into a typed "trusted" object; there is no verify-key gate available at
    this layer to make it safe. If a verified-decode constructor is needed later,
    it must take a required COSE verify key as an explicit parameter — that is a
    new design decision, not a mechanical carry-over.

    > TODO (hardening): security-01 — if callers actually need a verified
    > `EATClaimsSet.from_cwt(...)`, it must be added as a new method that requires
    > a COSE verify key parameter and performs signature verification before
    > decoding. Not added here; needs author decision on the key-provisioning API.
- `Location`, `DLOAEntry`, `SoftwareMeasurement`, `MeasurementResult` → keep (new EAT
  substructures). `Location` = EAT §4.2.10 device geo, distinct from excluded
  `GeographicResultClaims`.
- `DebugStatus`, `IntendedUse` → keep (new enums).

DROP from `jwt_cwt_objects2.py` (superseded): `EAR`, `EARAppraisal`, `VerifierID`,
`EARStatus`, `TrustTier`, `SignatureAlgorithm`, `HashAlgorithm`, `load`, `decode_cwt`,
`cwt_to_jwt`, `jwt_to_cwt`, `DecodedToken`, and private helpers `_b64u/_b64u_to_bytes/
_to_json/_readable_bytes/_drop_empty/_ALG/_HDR/_LABELS/_NAME/_BYTE_CLAIMS`. Unify the two
model bases (`_ClaimsModel` vs `ear.py`'s BaseModel+ConfigDict) onto one.

`bootseed`/`boot_seed` wire compatibility (contracts-02): `jwt_claims_to_cwt_claim_set`
must accept **both** `boot_seed` and `bootseed` as input aliases for one release (the
registry's canonical RFC name is `bootseed`; the old code silently used `boot_seed`).
Emit under the canonical `bootseed` name; document the alias in a code comment and in
Risks below.

Note: merged `cwt_jwt.py` ~1000+ lines; use section banners; split later if painful.

## `cwt_jwt_utils.py` — contents
Concatenate `cwt_utils.py` + `jose_jws.py` + `jose_hpke.py` + `cose_hpke.py`. Internal
cross-imports collapse (jose_hpke→jose_jws, cose_hpke→cwt_utils become same-file). External
deps unchanged. Retained public fns: `generate_es256_keypair`, `verified_jwt_to_signed_cwt`,
`convert_jwt_to_cwt`, `resign_cwt`, `jwt_to_cwt_claims`, `sign_es256`/`verify_es256`/
`p256_public_to_jwk`, `seal_*/open_*` (JOSE + COSE HPKE). `ALG` is split into `ES256_ALG`
and `HPKE0_ALG` per the de-collision in commit 1.

## Importer & attribute-rewrite edits (commit 2 — complete list)

### Import statement flips
| Old import | New import | Sites |
|---|---|---|
| `libattest.ear` | `libattest.formats.eat_ear.cwt_jwt` | `ra/verifier_client.py:40`, `verifier/eareat_cose_hpke/cose_hpke_verifier.py:41`, `verifier/eareat_hpke/eareat_hpke_verifier.py:33`, `tests/test_ear_model.py:14`, `prototypes/tpm_key_binding/{verifier.py:37,demo.py:29,test_key_binding.py:34}` |
| `formats.cwt_jwt` | `...eat_ear.cwt_jwt` | `quick_test.py:20`, `tests/test_cwt_jwt.py:17`; `cwt_utils.py:27`→intra-package `from .cwt_jwt import …` |
| `formats.cwt_utils` | `...eat_ear.cwt_jwt_utils` | `tests/test_quick_test.py:14`, `tests/test_cwt_jwt.py:23` |
| `formats.cose_hpke` | `...eat_ear.cwt_jwt_utils` | `verifier/eareat_cose_hpke/cose_hpke_verifier.py:40`, `formats/eareat_cose_hpke.py:33`, `attester/evidence_bridge.py:42`, `tests/test_cose_hpke_evidence.py:24` |
| `formats.jose_jws` | `...eat_ear.cwt_jwt_utils` | `prototypes/tpm_key_binding/verifier.py:38`, `tests/test_jose_jws.py` |
| `formats.jose_hpke` | `...eat_ear.cwt_jwt_utils` | `tests/test_jose_hpke_vector.py` |

### Bare attribute-access rewrites (operability-02 — not a single edit, ~25 sites)
The original plan under-counted this as "one non-mechanical edit" in `eareat_hpke.py`.
Every bare `jose_hpke.X`/`jose_jws.X`/`cwt_utils.X`/`cose_hpke.X` call site outside
the merged module must be rewritten to call the merged `cwt_jwt_utils` module (or
import the specific names directly), including the `jose_hpke.ALG`→`HPKE0_ALG` sites
already listed above. Enumerate and fix per file during commit 2:
- `formats/eareat_hpke.py` — `from libattest.formats import jose_hpke, jose_jws` at
  line 41, plus attribute calls through the file (seal/open, `jose_hpke.ALG` at
  line 103). Rewrite import to `from libattest.formats.eat_ear import cwt_jwt_utils`
  and rewrite every `jose_hpke.X`/`jose_jws.X` call site to `cwt_jwt_utils.X`.
- `verifier/eareat_cose_hpke/cose_hpke_verifier.py` — ~6 bare attribute-access sites
  (`cose_hpke.X`/`jose_hpke.ALG` at line 158) to rewrite in addition to the two
  import-statement flips already listed.
- `verifier/eareat_hpke/eareat_hpke_verifier.py` — ~9 bare attribute-access sites
  (`jose_hpke.X`/`cwt_utils.X`, including `jose_hpke.ALG` at line 125) to rewrite.
- `formats/cose_hpke.py` (pre-merge) — internal `cwt_utils.jwt_to_cwt_claims(...)`
  attribute call collapses to a same-file/import-by-name call once merged into
  `cwt_jwt_utils.py`; verify no stray `cwt_utils.` prefix survives the merge.
- `formats/eareat_hpke.py` (pre-merge) — internal `jose_jws`/`jose_hpke` attribute
  calls collapse the same way; verify no stray prefixes survive.
- Any remaining `from libattest.formats import jose_hpke, jose_jws` (or similar
  multi-name `from ... import`) elsewhere in `src/tests/prototypes` — grep per the
  Verification section below and rewrite each hit found.

Also: delete `jwt_cwt_objects2.py`; delete old `ear.py`, `formats/{cwt_jwt,cwt_utils,jose_jws,jose_hpke,cose_hpke}.py`; refresh `:mod:`/`:func:` docstring references (accuracy sweep). (Commit 3.)

## Domain glossary (`CONTEXT.md`)
Add an "EAT Claims Set" entry (Evidence claims-set, modelled by `EATClaimsSet`) mirroring
the existing EAR entry — makes the Evidence-vs-Result distinction explicit. Lands in
**commit 4** alongside the `EATClaimsSet` semantic work it documents.

## Verification
1. `python -m pytest -q` — all 182 tests green (baseline first, then after each commit).
   Pytest-green is necessary-not-sufficient (operability-03) — combine with the greps
   and `ruff` below before declaring a commit done.
2. Verification grep, corrected to catch bare names and multi-name `from` imports, not
   just dotted-module imports (operability-03 — the original grep was blind to
   `from libattest.formats import jose_hpke, jose_jws` and bare attribute calls):
   - `grep -rn '\blibattest\.ear\b\|\bformats\.cwt_jwt\b\|\bformats\.cwt_utils\b\|\bformats\.jose_jws\b\|\bformats\.jose_hpke\b\|\bformats\.cose_hpke\b' src tests prototypes` (dotted-import scan)
   - `grep -rn '\bjose_hpke\b\|\bjose_jws\b\|\bcwt_utils\b\|\bcose_hpke\b\|\bcwt_jwt\b' src tests prototypes | grep -v '/eat_ear/'` (bare-name scan, outside the new package)
   - `grep -rn 'from libattest\.formats import' src tests prototypes` (multi-name import scan)
   - `grep -rln 'libattest\.ear\b\|formats\.cwt_jwt\b\|formats\.cwt_utils\b\|formats\.jose_jws\b\|formats\.jose_hpke\b\|formats\.cose_hpke\b' README.md pyproject.toml prototypes/tpm_key_binding/README.md` (doc scan — extended per contracts-01/decision 3)
   All four must return only expected `eat_ear` paths (or nothing, for the doc scan).
3. `python -c "from libattest.formats.eat_ear import EATClaimsSet, EARToken, cose_cwt_to_jwt_view, generate_es256_keypair"` smoke import.
   Note: per security-02, `parse_ear_verdict` and `cose_cwt_to_jwt_view` are not
   flat-exported from `eat_ear/__init__.py` as *recommended* top-level API — they
   remain importable from `eat_ear.cwt_jwt` directly; only `verify_ear_jwt` and the
   other verified/typed entry points get the flat top-level export. Adjust the smoke
   import above to `from libattest.formats.eat_ear.cwt_jwt import cose_cwt_to_jwt_view`
   if `__init__.py` does not re-export it.
4. New `demo()` assert self-checks (commit 4):
   a. ES256 sign/verify + HPKE seal/open still work post-merge (exercises the
      ALG/b64u de-collision from commit 1 end-to-end).
   b. `jti` round-trips to the correct `cti` CWT-claim bytes through
      `EATClaimsSet.to_cwt_claims()` (exercises correctness-03 routing).
   c. Label 268 (`bootseed`) name assertion — confirms the registry emits the
      canonical RFC name, not the old `boot_seed` (exercises contracts-02).
5. `ruff check` clean — mandatory verification step (operability-04), not optional
   "if wired in CI". Run after commit 3 (path update) and again after commit 4.
6. `mypy` if wired in CI.

## Risks / call-outs
- Wide diff touches production verifiers — mitigated by grep + full suite, and now by
  the 4-commit revertable staging (operability-01) instead of one big-bang diff.
- Registry-as-source could drop a name only in python-cwt — mitigated by CWT_CLAIM_NAMES fallback.
- `ALG` name collision between `jose_jws`/`jose_hpke` when concatenated into
  `cwt_jwt_utils.py` is a correctness blocker, not cosmetic — de-collided explicitly
  in commit 1 (`ES256_ALG`/`HPKE0_ALG`), with all 3 external `jose_hpke.ALG`
  call-sites rewritten in commit 2 (correctness-01).
- `boot_seed`→`bootseed` wire rename: accepting both names as input aliases for one
  release avoids silently breaking any caller currently sending `boot_seed`; emit
  under the canonical `bootseed` name; remove the alias in a follow-up release once
  callers have migrated (contracts-02).
- `libattest.ear` is documented public API — hard move requires doc refresh
  (README.md:18, pyproject.toml:22, prototypes/tpm_key_binding/README.md:29-30), no
  compatibility shim, per human decision 3 (contracts-01).
- `eareat_hpke.py` (and the two `eareat_*_verifier.py` files) attribute-access
  rewrite is not a single edit — ~25 sites across 3 production files, enumerated
  above (operability-02).
- Merged files are large (deliberate, per user call).
