# TPM Docker demo for libattest-py

This folder contains the self-contained libattest-py Docker setup for the IBM
TPM simulator.  The simulator can be started in one terminal and the Python
demos or interactive TPM tooling can be run from another container.

The local libattest files are:

- `docker/tpm-demo/docker-compose.yml`
- `docker/tpm-demo/Dockerfile.client`
- `docker/tpm-demo/Dockerfile.tpmsim`
- `docker/tpm-demo/demo.py`
- `docker/tpm-demo/provision.sh` / `provision_ek.py` — device-side EK provisioning
- `docker/tpm-demo/ek_http_verifier.py` — demo verifier HTTP surface (stdlib)
- `docker/tpm-demo/ek_http_demo.py` — end-to-end EK-over-HTTP flow

## Build the images

From the repository root:

```bash
docker compose -f docker/tpm-demo/docker-compose.yml build
```

Because the interactive client and one-shot demo services are behind compose
profiles, an explicit all-service build on a clean machine is:

```bash
docker compose -f docker/tpm-demo/docker-compose.yml build tpmsim client demo
```

This builds:

- `libattest-tpmsim:latest` — IBM Software TPM 2.0 simulator (`tpm_server`)
- `libattest-tpm-client:latest` — Ubuntu 24.04 with tpm2-tss, tpm2-pytss,
  and libattest Python dependencies

The client image pins `tpm2-tss` before installing `tpm2-pytss` so the Python
CFFI bindings are built against the same headers and libraries present at
runtime.

## Terminal 1: start the TPM simulator

```bash
docker compose -f docker/tpm-demo/docker-compose.yml up -d tpmsim
```

The simulator listens on the compose network as `tpmsim`. The host ports default
to non-conflicting values so this stack can run beside another local simulator
if it is already using `2321`/`2322`:

- host command channel: `${TPMSIM_COMMAND_PORT:-12321}` → container `2321`
- host platform channel: `${TPMSIM_PLATFORM_PORT:-12322}` → container `2322`

If you want the canonical host mssim ports, start it with:

```bash
TPMSIM_COMMAND_PORT=2321 TPMSIM_PLATFORM_PORT=2322 \
  docker compose -f docker/tpm-demo/docker-compose.yml up -d tpmsim
```

Check health/logs:

```bash
docker compose -f docker/tpm-demo/docker-compose.yml ps
docker compose -f docker/tpm-demo/docker-compose.yml logs -f tpmsim
```

## Terminal 2: run the readable libattest demos

```bash
docker compose -f docker/tpm-demo/docker-compose.yml run --rm demo
```

This runs:

```bash
python docker/tpm-demo/demo.py   # platform + key + EK-over-HTTP demos
```

Both demos perform **real** TPM operations via `tpm2-pytss`
(`libattest.attester.tpm_client.TpmClient`) against the live `tpmsim`:

- the platform demo provisions an EK + AK, runs a real `TPM2_Quote`, and
  appraises it with `TpmPlatformVerifier` (signature + freshness + PCR digest);
- the key-attestation demo runs `TPM2_MakeCredential`/`ActivateCredential` to
  recover the verifier `seed` and checks it equals the seed the verifier wrapped
  for `(EK, AK Name)` — the credential-activation core of the v5 flow.

They require `tpm2-pytss` and a reachable TPM, which the `client` image and the
healthy `tpmsim` service provide.

The platform demo runs end to end; the key demo exercises the credential-activation
core (seed recovery). The verifier-side building blocks live in the verifier
bridge + TPM verifier classes:

- `verify_bridge.make_credential_challenge()` (→ `TpmKeyAttestVerifier.make_challenge()`)
  runs software `TPM2_MakeCredential`, generating/retaining `seed` and returning
  only `encSeed`/`encSecret` to the client.
- `verify_bridge.verify_key_attest()` (→ `TpmKeyAttestVerifier.verify()`) appraises
  a `KeyAttestEvidence` statement (certify + name-binding + PoP-over-seed); the full
  statement path needs a subject key + AK cert chain and is exercised by the
  remote-attest-e2e docker stack, not this single-process demo.
- `TpmPlatformVerifier.verify_quote_signature()` verifies TPM2_Quote freshness
  and the AK signature over the exact `TPMS_ATTEST` bytes.

### EK-over-HTTP demo (`ek_http_demo.py`)

The third demo splits the credential-activation core across a real HTTP boundary
so you can see how a verifier obtains the endorsement-key public area. The key
point: software `TPM2_MakeCredential` needs the EK's **whole** `TPM2B_PUBLIC`
(its `nameAlg`, `objectAttributes` and the `parameters.symmetric` used for the
outer wrap), **not** just the raw public key — and an X.509 EK certificate only
carries the `SubjectPublicKeyInfo`. So the device submits *both*.

Flow:

1. **Device provisions the EK** (`provision.sh` → `provision_ek.py`) and writes
   two artifacts:
   - `ek_tpm2b_public_key.raw` — the marshalled `TPM2B_PUBLIC` (what
     MakeCredential consumes);
   - `ek_cert_chain.pem` — a demo EK certificate carrying the EK public key.
2. **`POST /demo/ek/submit`** — the device sends `ek_cert_chain.pem` + the raw
   bytes. The verifier (`EkStore`) unmarshals the `TPM2B_PUBLIC` via `tpm2-pytss`,
   enforces the **bind check** (cert `SubjectPublicKeyInfo` == `TPM2B_PUBLIC` key),
   and stores the public area keyed by the leaf cert's SHA-256 fingerprint
   (`ek_id`).
3. **`POST /demo/ek/challenge`** — the device sends `ek_id` + AK Name; the
   verifier looks up the stored `TPM2B_PUBLIC`, runs software MakeCredential over
   `(EK, AK Name)`, retains the `seed`, and returns only `encSeed`/`encSecret`.
4. **Device runs `TPM2_ActivateCredential`** to recover the seed and
   **`POST /demo/ek/verify-seed`** with `H(seed)`; only a TPM holding both the EK
   and the named AK can produce it.

> **Demo EK certificate caveat.** A genuine EK is decrypt-only and *cannot sign*,
> and the IBM simulator ships no manufacturer EK certificate at its NV index. The
> demo therefore mints a stand-in EK leaf signed by an ephemeral issuer key,
> purely to have a valid X.509 structure. The verifier uses trust-on-first-submit
> (TOFU): it does **not** validate the chain signature — it checks only that the
> cert's key matches the `TPM2B_PUBLIC`. A real deployment would validate the leaf
> against the TPM manufacturer's Endorsement CA before trusting the mapping. The
> *key* provisioning is genuine TCG-correct; only the *cert* is synthesized.

The reusable verifier logic lives in the library
(`libattest.verifier.ek_store.EkStore`); `ek_http_verifier.py` is a thin stdlib
`http.server` wrapper (the minimal client image ships no web framework). The
client calls are `AttestClient.submit_ek()` /
`request_credential_challenge()` / `report_seed()`.

Run just this demo or its tests inside the client shell:

```bash
python docker/tpm-demo/ek_http_demo.py
pytest docker/tpm-demo/test_ek_http_demo.py -q   # + the bind-check rejection test
bash docker/tpm-demo/provision.sh ek-artifacts   # writes the two artifacts only
```

The demo package is isolated inside libattest-py; it does not require any
external example repository at runtime.

There is also a wrapper script:

```bash
docker compose -f docker/tpm-demo/docker-compose.yml run --rm client \
  python docker/tpm-demo/demo.py
```

## Terminal 2: open an interactive client shell

```bash
docker compose -f docker/tpm-demo/docker-compose.yml run --rm client
```

Inside the container, the repository is mounted at `/workspace` and the client
has these environment variables preconfigured:

```bash
TCTI=mssim:host=tpmsim,port=2321
PYTHONPATH=/workspace/src
```

Examples inside the client shell:

```bash
python docker/tpm-demo/platform_attest_demo.py
python docker/tpm-demo/key_attest_demo.py
python docker/tpm-demo/ek_http_demo.py
pytest docker/tpm-demo/test_demo.py docker/tpm-demo/test_ek_http_demo.py -q
pytest tests/test_tpm_pcr_selection_json.py tests/test_key_attest_v5.py -q
```

Or run quick Python experiments against the mounted source tree:

```bash
python - <<'PY'
from libattest.formats.tpm import encode_tpm_pcr_selection_info_from_parts
print(encode_tpm_pcr_selection_info_from_parts(pcrs=[0, 1, 2, 3, 4], hash_alg_id=0x000B).hex())
PY
```

## Stop and clean up

```bash
docker compose -f docker/tpm-demo/docker-compose.yml down
```

The simulator container uses `tpm_server -rm`, so each simulator container start
remanufactures TPM state for reproducibility.
