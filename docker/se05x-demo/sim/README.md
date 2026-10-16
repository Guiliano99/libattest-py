<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# SE050 simulator inputs

`../Dockerfile.se05xsim` builds wolfSSL's SE050 simulator (`SE050Sim`, the `tcp_server` binary)
from pinned sources plus the files in this directory:

| File | What it is | SHA-256 |
|---|---|---|
| `0001-Extend-SE050Sim-for-SE05x-API-regression-coverage.patch` | Upstream [PR #19][pr19], commit 1 of 2, vendored unchanged (`git format-patch` output): per-object policy and origin, `ReadObjectAttributes`, policy enforcement on read, write and delete | `5f388b0852c4caa85cc4ce646d900983caea74e48577127ed552a8fd6728dd06` |
| `0002-Extend-SE05x-API-regression-coverage.patch` | [PR #19][pr19], commit 2 of 2 (head [`11fc044`][pr19-head]), vendored unchanged: wolfCrypt regression tests | `a03b795eb3904bcb08a227cff37b207d1b7639c3e488273010779567ddb8916f` |
| `0003-se05x-attestation.patch` | Our patch on top of PR #19 (`git diff`, apply with `git apply`): applet-7.2 attested `ReadObject`, `GetTimestamp`, the provisioned attestation key and chip id, the policy checks attestation needs, and tests | `9c3a3db6c16e1e088438a6948bdbd2209bca3002bce12b1ca49156ea987cf330` |
| `Cargo.lock` | The crate's resolved dependencies. Upstream commits none (`SE050Sim/.gitignore`); the build copies this one and uses `--locked` | `df20ff8a84e4b84fef5b4bdf7d1dca6b94190984818190be8fbf25bf3a3ba390` |

The Dockerfile also fetches, by commit SHA:

- `wolfSSL/simulators` at upstream `main` commit [`ee28091`][upstream], the base of PR #19;
- `LinuxJedi/nxp-se050` at [`af49819`][driver] into `SE050Sim/nxp-se050`, the crate's
  dev-dependency. Cargo resolves it even for `cargo build --bin tcp_server`.

Upstream `ee28091` plus `0001` and `0002` gives exactly the PR #19 head: both have the git tree
`04494a3af95f3d62d6760b0e692cd25a75420c4e`. The build never fetches the PR branch, which can change
until it is merged.

## What 0003 does

Details and the reasons behind each choice are in
[`docs/plans/2026-09-23-se05x-freshness-nonce-length.md`](../../../docs/plans/2026-09-23-se05x-freshness-nonce-length.md),
section "What the simulator attestation patch does". In short:

- Attested `ReadObject` (INS `22`, also `62`/`A2`/`E2`) in the applet-7.2 format: strict request
  tags, a 16-byte freshness value (`TAG_7`), SHA-224/256/384/512. The ECDSA signature covers the hash
  of the plain command without Le (extended Lc) and the response TLVs. The 3.1.1 personality refuses
  it with `6985`.
- `GetTimestamp` (`80 04 00 3D`) on every personality. The timestamp is strictly increasing within
  a run and across restarts. `tcp_server` waits for the next whole second once at start-up, before
  it listens.
- At start-up, the attestation key `0xF0000012` (P-256; READ and ATTESTATION only; origin
  PROVISIONED) and the 18-byte chip id `0x7FFF0206` (READ only) are provisioned. Both survive
  DeleteAll.
  - `SE050_SIM_ATTEST_SEED` unset or empty (the default): both come from 32 bytes of OS
    randomness, so every start is a new chip whose key nobody else can derive.
  - Any other value: both derive deterministically from it (same seed, same key). Use this only
    where a stable key matters more than secrecy; anyone who knows the seed can forge Evidence.
  - The log says which of the two was used.
- Policy fixes that attestation relies on: signing needs ALLOW_SIGN and ECDH needs ALLOW_KA once a
  policy is attached; FORBID_ALL blocks attestation; the origin follows the latest key value.
- Tests: unit tests in `src/handlers/attest.rs` and end-to-end T=1 tests (plain, chained, Platform
  SCP03) in `tests/attestation.rs`. The crate has 141 tests in total, all run by the image's `test`
  stage.

## Refreshing when PR #19 changes

1. Fetch the new PR head and regenerate `0001`/`0002` from its merge base with upstream `main`:

   ```sh
   git clone https://github.com/wolfSSL/simulators sim && cd sim
   git fetch https://github.com/LinuxJedi/simulators <new-pr-head>
   base=$(git merge-base origin/main FETCH_HEAD)
   git checkout "$base"
   git format-patch -o ../patches "$base"..FETCH_HEAD
   git -c user.name=x -c user.email=x@x am ../patches/*.patch
   test "$(git rev-parse 'HEAD^{tree}')" = "$(git rev-parse 'FETCH_HEAD^{tree}')"
   git tag pr19-base
   ```

   If the base moved, update `SIM_SHA` in `../Dockerfile.se05xsim`. If the number of PR commits
   changes, update the `COPY` and `git am` lines as well.
2. Re-apply `0003` (`git apply --3way 0003-se05x-attestation.patch`) and resolve any conflicts. Then
   fetch the driver into `SE050Sim/nxp-se050`, copy `Cargo.lock` into `SE050Sim/se050-sim/` and run
   `cargo test --locked --all-targets -- --test-threads=1` there. If `Cargo.toml` changed and
   `--locked` fails, run `cargo generate-lockfile` and take the new lockfile.
3. Export the patch again: `git add -A && git diff --cached refs/tags/pr19-base > 0003-se05x-attestation.patch`.
4. Update the SHA-256 table above, build the image's `test` stage, and run the demo.

When PR #19 is merged, set `SIM_SHA` to a `main` commit that contains it, and delete `0001`, `0002`
and the `git am` step.

## Licence

SE050Sim is GPL-3.0-or-later. The three patches and `Cargo.lock` are therefore GPL-3.0-or-later too
(declared in `REUSE.toml`, licence text in `LICENSES/GPL-3.0-or-later.txt`). `0001`/`0002` are
wolfSSL's; `0003` modifies wolfSSL's files and adds files copyright Siemens AG. The Dockerfile and
this README are Apache-2.0.

The image contains GPL-3.0-or-later software. Build it locally as `libattest-se05xsim:local` and
never push it to a registry: distributing the image would bring GPL source-offer obligations with
it.

[pr19]: https://github.com/wolfSSL/simulators/pull/19
[pr19-head]: https://github.com/LinuxJedi/simulators/commit/11fc0440b66cb7cce5f8ed55006ee427b9b45db6
[upstream]: https://github.com/wolfSSL/simulators/commit/ee280919229cceb7a5504b5dd40af90d8c0731cb
[driver]: https://github.com/LinuxJedi/nxp-se050/commit/af49819d1e09e25dfa438a8858f7ed89cd53944a
