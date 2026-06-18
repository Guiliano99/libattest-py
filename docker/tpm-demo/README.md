# TPM Docker demo for libattest-py

This folder contains the self-contained libattest-py Docker setup for the IBM
TPM simulator.  The simulator can be started in one terminal and the Python
demos or interactive TPM tooling can be run from another container.

The local libattest files are:

- `docker/tpm-demo/docker-compose.yml`
- `docker/tpm-demo/Dockerfile.client`
- `docker/tpm-demo/Dockerfile.tpmsim`
- `docker/tpm-demo/demo.py`

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
python docker/tpm-demo/demo.py   # platform_attest_demo + key_attest_demo
```

Both demos perform **real** TPM operations via `tpm2-pytss`
(`libattest.attester.tpm_client.TpmClient`) against the live `tpmsim`:

- the platform demo provisions an EK + AK, runs a real `TPM2_Quote`, and
  appraises it with `TpmPlatformVerifier` (signature + freshness + PCR digest);
- the key-attestation demo runs `TPM2_MakeCredential`/`ActivateCredential` to
  recover the verifier `seed`, then verifies the `KeyAttestPoP` signature over
  that recovered seed with `TpmKeyAttestVerifier`.

They require `tpm2-pytss` and a reachable TPM, which the `client` image and the
healthy `tpmsim` service provide.

This Docker demo exercises the full key/platform attestation flow end to end.
The verifier-side building blocks live in the TPM verifier classes:

- `TpmKeyAttestVerifier.build_activation_challenge()` creates the verifier side
  of a TPM2_ActivateCredential challenge by generating/storing `seed` and
  returning only `encSeed`/`encSecret` to the client.
- `TpmKeyAttestVerifier.verify_activation_pop()` verifies the post-activation
  `KeyAttestPoP` signature over the recovered `seed`.
- `TpmPlatformVerifier.verify_quote_signature()` verifies TPM2_Quote freshness
  and the AK signature over the exact `TPMS_ATTEST` bytes.

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
pytest docker/tpm-demo/test_demo.py -q
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
