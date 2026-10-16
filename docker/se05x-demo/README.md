<!--
SPDX-FileCopyrightText: Copyright 2026 Siemens AG
SPDX-License-Identifier: Apache-2.0
-->

# SE05x attestation demo for libattest-py

This folder runs NXP SE05x key attestation end to end against wolfSSL's SE050 simulator,
patched to answer applet-7.2 attested reads. It shows that:

- an RA issues a 16-byte nonce;
- a P-256 key generated inside the SE is read with attestation, with the nonce as the SE's
  signed freshness value;
- the RA's `RemoteAttestationEngine` routes the Evidence through `se05x_profile` to
  `Se05xAttestVerifier`, which checks it and issues an EAR;
- the RA accepts that EAR, and refuses the same Evidence when it is replayed.

Nothing here is NXP-rooted. The demo shows the protocol, not the security of a real secure
element (see [Caveats](#caveats)).

The files:

- `docker-compose.yml`: the `se05xsim`, `provision`, `test` and `demo` services and the `trust` volume
- `Dockerfile.se05xsim`, `sim/`: the patched simulator (GPL-3.0-or-later; see `sim/README.md`)
- `Dockerfile.client`: `python:3.13-slim` (pinned by digest) with libattest's dependencies
  and its `testing` extra; the source tree is bind-mounted read-only at `/workspace`
- `provision.py`: certifies the simulator's attestation key under an ephemeral demo root
- `se05x_demo.py`: the narrated RA flow, in one process
- `test_se05x_demo.py`: the live tests
- `check_key_per_start.py`: host-side check that every simulator start has a new attestation key

## Run it

From the repository root:

```bash
make se05x-build   # build libattest-se05xsim:local and libattest-se05x-client:local
make se05x-test    # provision, run test_se05x_demo.py, then check_key_per_start.py on the host
make se05x-demo    # provision, then run se05x_demo.py
make se05x-down    # stop the stack and remove the trust volume
```

The first simulator build compiles Rust from pinned sources and takes a few minutes. The same
steps without make:

```bash
docker compose -f docker/se05x-demo/docker-compose.yml build
docker compose -f docker/se05x-demo/docker-compose.yml run --rm test
PYTHONPATH=src python docker/se05x-demo/check_key_per_start.py   # host; needs the built image
docker compose -f docker/se05x-demo/docker-compose.yml run --rm demo
docker compose -f docker/se05x-demo/docker-compose.yml down -v
```

`test` and `demo` start the simulator and wait for it to be healthy, then wait for `provision`
to finish. The simulator has no host port. To talk to it from the host, uncomment the
`127.0.0.1:${SE05XSIM_PORT:-18050}:8050` mapping in `docker-compose.yml`. Then run the scripts
with `SE05X_HOST=127.0.0.1 SE05X_PORT=18050 TRUST_DIR=<dir> PYTHONPATH=src`.

`check_key_per_start.py` needs the host's Python environment (`make setup`) and Docker. It
starts `libattest-se05xsim:local` four times with `docker run`, each on a free `127.0.0.1` port,
and removes each container afterwards. It passes when two unseeded starts expose different
`0xF0000012` keys and two starts with the same `SE050_SIM_ATTEST_SEED` expose the same key.

## The flow

1. **Provisioning** (`provision`, one-shot). This service plays the manufacturer. It reads the
   attestation public key `0xF0000012` and the 18-byte chip id `0x7FFF0206`. It mints a root CA
   named `libattest demo SE05x attestation root (not NXP)` and, under that root, a certificate
   for the attestation key; the certificate's subject `serialNumber` is the chip id in hex. It
   writes the DER certificate into the SE as the binary file `0xF0000013` and writes only the
   root certificate to `/trust/root.pem`. The root private key exists only in that container's
   memory and is gone when the container exits. A second run against the same simulator start
   mints a new root and replaces both files.
2. **Nonce.** The RA builds its engine as `se05x_demo.make_engine` does:

   ```python
   profiles = ProfileRegistry()
   profiles.register(se05x_profile(verifier=Se05xAttestVerifier(roots=[root], policy_id="policy:SE05X/demo-sim-root")))
   engine = RemoteAttestationEngine(profiles, NonceStore(nonce_bytes=16), ear_policy=EarAcceptancePolicy())
   ```

   and `build_nonce_response` returns a 16-byte nonce.
3. **Evidence.** The Attester deletes and regenerates the key `0x10AA0002` inside the SE with the
   policy READ | SIGN | VERIFY | DELETE (no ATTESTATION: this key is attested, it does not attest).
   It reads the certificate `0xF0000013` back, and `Se05xAttestProvider.generate_evidence(nonce)`
   does the attested read with the nonce unchanged as `TAG_7`. The SE signs the SHA-256 of the
   command, which contains `TAG_7`, together with the response: the key's public point, the chip
   id, the key's attributes (object id, type, policy, origin), its size and a timestamp.
4. **Bundle.** `prepare_asn1_attestation_statement` wraps the DER `Se05xAttestEvidence`, and
   `prepare_attestation_bundle` adds the attestation certificate. Only the leaf is added; the root
   is the verifier's trust anchor.
5. **Appraisal.** `engine.verify_bundle(bundle, tx_id, pubkey=<SPKI of the SE key>)`. The
   verifier checks the command shape, the attestation key id, the algorithm (ECDSA with SHA-256),
   `TAG_7` against the RA nonce, the response, key type and size, origin INTERNAL, the certificate
   chain to `root.pem`, the signature, and that the attested key is the to-be-certified key. The
   RA then checks the EAR's signature against the verifier's pinned key, and checks its nonce and
   age.
6. **Replay.** The RA issues a new nonce under the same transaction, and the same bundle is
   refused: its signed `TAG_7` is the old nonce.
7. **Proof of possession.** `Se05xClient.sign_digest(0x10AA0002, sha256(...))` returns a DER ECDSA
   signature that verifies with the attested key. A CSR is signed this way, so the private key
   never leaves the SE.

`se05x_demo.py` exits with 0 only if step 5 is accepted and step 6 is refused.

## The EAR

On success the verifier issues one EAR (ES256 JWT), and `test_se05x_demo.py` asserts exactly these
submods:

```json
{"SE05X": {"ear.status": "affirming",
           "ear.trustworthiness-vector": {"instance-identity": 2},
           "ear.appraisal-policy-id": "policy:SE05X/demo-sim-root"}}
```

`eat_nonce` echoes the RA nonce. On any failed check the verifier issues **no EAR**: it returns
`contraindicated` with the reason, and the engine passes that verdict through.

**`instance-identity` = 2** (draft-ietf-rats-ar4si-10 §2.3.4): "The Attesting Environment is
recognized, and the associated instance of the Attester is not known to be compromised." Here
"recognized" means that the Attester holds the key of an end-entity signing certificate issued
under the configured root and has signed the fresh RA nonce with it. The policy id says which root
that is. The verifier rejects a CA certificate, or one whose keyUsage excludes
`digitalSignature`, as the attestation certificate. It cannot tell an SE05x attestation key from
any other signing key under the same root, so the root must certify only SE05x attestation keys
(see [Caveats](#caveats)).

Key provenance is a gate, not a claim: origin INTERNAL, type, size, object id, `TAG_1` and the
binding to the subject key must all pass for `affirming`. No AR4SI claim describes where one key
came from.

The EAR uses Veraison's wire format with dotted keys (profile `tag:github.com,2023:veraison/ear`)
and the AR4SI -10 claim labels. Neither draft is an RFC yet.

## Caveats

- **The demo root is not NXP's.** `instance-identity` = 2 therefore means "certified by an
  ephemeral root that `provision` minted", and the policy id `policy:SE05X/demo-sim-root` says
  so, including inside a certificate's EAR extension. `hardware` = 2 would belong only to a
  deployment whose roots are NXP's attestation CA **and** that has a revocation input. Neither
  exists here.
- **The roots must certify only SE05x attestation keys.** The leaf certificate, not the `TAG_5`
  key id in the command, fixes who signed the Evidence. So any other end-entity signing key under
  a configured root can forge Evidence. With NXP, pin the CA that issues attestation
  certificates, not a root that also certifies other keys.
- **The SE is a simulator.** Its attestation private key lives in a process on the Docker host.
  Its binding is only as strong as that process.
- **`SE050_SIM_ATTEST_SEED` makes the claim false.** Unset or empty (the default), the simulator
  draws a new attestation key and chip id at every start, and `check_key_per_start.py` proves it.
  Compose never sets it and does not take it from the host shell.
  With a seed, anyone who knows the seed can derive the key and forge Evidence, so seeded runs are
  for reproducible tests only.
- **An omitted claim means "no claim", not "good".** The other six AR4SI claims (configuration,
  executables, file-system, runtime-opaque, storage-opaque, sourced-data), and `hardware`, are
  omitted. The Evidence says nothing about them (AR4SI §3.1).
- **The chip id is signed but not bound to the certificate.** The SE signs its chip id into
  every attested read, and `provision` names it in the certificate subject, but the verifier does
  not compare the two.
- **The EAR carries no Identity Evidence.** AR4SI §2.2 asks for Identity Evidence in the result,
  so that the result can be tied to the Attesting Environment that was appraised. In this
  background-check flow the RA is the challenger, and the one-shot nonce ties the EAR to the
  exchange. The standard fix, EAR PR #77 (`ear_verified_attester_key`), is still open and is not
  implemented.
- **The simulator is GPL-3.0-or-later.** `libattest-se05xsim:local` is built locally from pinned
  sources plus the patches in `sim/`. Never push the image to a registry.
- **The nonce size is set per store, not per profile.** An RA that served both SE05x and TPM
  attesters from one `NonceStore(nonce_bytes=16)` would also give 16-byte nonces to the TPM path.
  That is still secure, but it changes existing behaviour, and 16 bytes is too short for
  technologies that need 32 bytes or more. The demo runs its own RA.
- **The engine ignores `NonceRequest.len`** (the freshness draft says the RA SHOULD honour it).
  The Attester omits `len`, and it fails closed on any nonce that is not 16 bytes.
- **External MockCA side finding.** Its `validate_nonce_request` calls `len()` on the decoded
  ASN.1 integer `NonceRequest.len`. That raises `TypeError` once its `min_nonce_length` knob is
  set and `len` is present. The knob defaults to `None`, so the path is dormant.
- **Timestamp continuity is not checked.** AN13254 wants consecutive timestamps. The single-use
  RA nonce already rules out replay.
- **Placeholder identifiers.** The statement and nonce OIDs sit on the placeholder arc
  `1.3.6.1.4.1.99999`. The media type `application/vnd.nxp.se05x-attestation+der` is also a
  placeholder.

Details and sources:
[`docs/plans/2026-09-23-se05x-attestation-implementation.md`](../../docs/plans/2026-09-23-se05x-attestation-implementation.md)
(section "EAR trust vector") and
[`docs/plans/2026-09-23-se05x-freshness-nonce-length.md`](../../docs/plans/2026-09-23-se05x-freshness-nonce-length.md)
(section "Limitations").

## Offline golden vector

`tests/data/se05x/golden_vector.json` holds one attested read captured from this simulator with a
random attestation key: a P-256 key generated in the SE (policy READ | SIGN | VERIFY | DELETE) and
a random 16-byte nonce. It records the nonce, the recorded command, the response body, the
attestation and subject SPKIs, the SHA-256 of `sim/0003-se05x-attestation.patch` and the capture
date. `tests/test_se05x_golden.py` runs in the ordinary unit tests, with no Docker. At test time
it mints a demo root and a certificate over the captured attestation key, so the vector never
expires. It checks that `Se05xAttestVerifier` affirms the Evidence with the exact submods, and
that a flipped response byte or another nonce is `contraindicated`. The bytes come from the Rust
simulator and are parsed by the Python codec, so the check is not circular.

Recapture the vector when `sim/0003` changes; a golden test fails until you do. With the host
port mapping enabled, run `provision.py`, then use `Se05xClient` to regenerate `0x10AA0002` with
the policy above and call `attested_read(0x10AA0002, os.urandom(16))`. `read_object` returns the
two public keys.

## Using it in a CMP end-to-end example

libattest needs no changes for a MockCA that serves only SE05x attesters, or only routes that
accept 16-byte nonces. The nonce size is set per `NonceStore`, and the MockCA has one engine and
one store for all its routes. A MockCA that also serves PSA or CCA (32 to 64-byte nonces) needs a
per-profile nonce size, which libattest does not have yet. The MockCA must:

0. **Use libattest's by-name OID accessors.** `mock_ca/attestation_routes.py` imports
   `resolve_tpm_pcr_selection_oid` from `libattest.formats.tpm` and `ID_TCG_ATTEST_CERTIFY` /
   `ID_TCG_ATTEST_QUOTE` from `libattest.ra`. None of them exists in this libattest, so the MockCA
   does not start. Use `get_oid_for_stmt_name`, `get_nonce_request_oid_for_name` and
   `get_nonce_response_oid_for_name` from `libattest` instead.
1. **Register the profile with an in-process verifier**, once, when
   `build_profile_registry_from_environment` builds the registry:

   ```python
   profiles.register(se05x_profile(verifier=Se05xAttestVerifier(roots=roots, policy_id="policy:SE05X/<trust-anchor class>")))
   ```

   `roots` must be CAs that certify only SE05x attestation keys (for NXP, the CA that issues
   attestation certificates). With this demo, load `root.pem` from the `trust` volume through an
   environment variable, for example `SE05X_ATTEST_ROOTS`. `provision` mints a new root on every
   run. So start the MockCA after it (`depends_on: provision: condition:
   service_completed_successfully`), and restart the MockCA whenever `provision` or the simulator
   restarts. There is no remote SE05x verifier service, so there is no `PROFILE_BUILDERS` entry.
2. **Issue 16-byte nonces** with `NonceStore(nonce_bytes=16)`. The SE signs the nonce unchanged,
   and both the Attester and the verifier refuse any other length. In the GenM leg, answer with
   `engine.build_nonce_response(tx_id, request_type_oid, ...)`, which sets `respTypeInfo.type` to
   `se05x-attest-response`. Today the MockCA calls `engine.issue_nonce` and then
   `prepare_nonce_response_from_request`, which echoes the request OID. The SE05x Attester
   ignores that field, but a client that checks it refuses the response.
3. **Pass the to-be-certified key** as `engine.verify_bundle(bundle_der, tx_id, pubkey=spki)`.
   `spki` is SubjectPublicKeyInfo DER re-encoded through `cryptography`
   (`public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)`). It is never the
   `[6]`-tagged `certTemplate.publicKey` field. For ir, cr and kur, take the key from
   `get_public_key_from_cert_req_msg(pki_message["body"][name][0])`; for p10cr, take it from
   `keyutils.load_public_key_from_spki(cri["subjectPKInfo"])`. Today `mock_ca/rats_handler.py`
   calls `verify_bundle(bundle_der, tx_id)` without it. The engine refuses that with "key
   attestation requires the to-be-certified SubjectPublicKeyInfo".
4. **Build the request with the SE key** (client side). Keep this order: generate the key and do
   the attested read, add the bundle to the request, then sign. `se05x_demo.attest` deletes and
   regenerates the key, so calling it after signing breaks the binding. Bundle the attestation
   (leaf) certificate and any intermediates, never the root. A root in the chain counts as a CA
   below itself, so a root with `pathLenConstraint` 0, like the demo root, rejects the chain.
   Neither libattest nor the cmp-test-suite has a helper that places the bundle, so keep that
   code in the client.
   - **ir or cr (CRMF):** add `Extension(id-aa-attestation, critical=False, extnValue=<bundle
     DER>)` to `certTemplate.extensions`, where the MockCA reads it. Then sign `POPOSigningKey`
     over DER(`certReq`). The signer is a small `ec.EllipticCurvePrivateKey` subclass whose
     `sign(data, ECDSA(SHA256()))` returns `se.sign_digest(key_id, sha256(data))`, which the
     cmp-test-suite's `sign_data` accepts.
   - **p10cr (PKCS#10):** build the `CertificationRequestInfo` with pyasn1, including the
     id-aa-attestation attribute, because `cryptography`'s CSR builder cannot carry it. Hash it
     with SHA-256, sign the digest with `se.sign_digest(key_id, digest)`, and assemble the CSR with
     `ecdsa-with-SHA256`.

   Either way, that is the proof of possession, and the private key never leaves the SE.
5. **Embed the EAR in the certificate.** The MockCA already does this:
   `RatsHandler._ear_encoder_for` calls the profile's `encode_ear_extension`, and
   `se05x_profile`'s default OID is the MockCA's default `EAR_OID`. `outcome.first_ear_extension`
   returns the same `(extension OID, extnValue DER)`. Keep `ear_policy=None` on the MockCA's
   shared engine unless every route has an EAR trust anchor: `EarAcceptancePolicy` refuses a
   verdict it has no anchor for, and the remote TPM routes have none. The SE05x verifier runs
   in-process.
