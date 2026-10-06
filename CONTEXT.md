# CONTEXT

Glossary for the NXP EdgeLock remote-attestation integration (one demo per
branch; this branch: `demo/docker_RATS_NXP`).

## Terms

- **Device attestation (ELE)** — the SoC's own statement about itself:
  fused identity (`uid`, `soc_id`, `lmda`, ROM-patch hash, firmware hash),
  signed by the factory device-attestation key. Answer to "is this really an
  i.MX93 in this state?"

- **Key attestation (ELE)** — the SoC's signed certification that a key in
  its key store is the one presented for enrollment (the `0x74`
  key-attestation certificate). The ELE analogue of TPM `TPM2_Certify`.
  Answer to "is this enrolled key resident and attested by the SoC?"

- **Attested read (SE05x)** — the SE05x's generic primitive: an object
  (key/credential/data) read accompanied by a signature from the
  chip-unique attestation key over value + UID + attributes + timestamp.

- **Statement** — the opaque, OID-typed payload of one
  `AttestationStatement.stmt`. Carried as an OCTET STRING; parsed only by
  the OID-keyed verifier profile. (See `docs/adr/0001`.)

- **Statement OID** — the OBJECT IDENTIFIER selecting a statement format and,
  via `VERIFIER_OID_ROUTES`, the verifier URL. The CA/RA's only knowledge of
  the format.

- **RA nonce** — the 32-byte one-shot nonce issued by the RA (MockCA) per
  CMP transaction, carried in the `NonceResponse`. ELE evidence binds
  `nonce[:16]` (signed inside the statement); SE05x has **no** RA-nonce
  binding (its freshness is the SE-internal timestamp).

- **2GO** — NXP EdgeLock two-go (factory-to-OEM) provisioning data; in
  evidence it appears as the signed "2GO-TLV" certificate buffer of key
  attestation.

- **SimNXP 2GO** — the simulator-generated stand-in for NXP's 2GO trust
  anchor. Statements verifying against it are valid **only inside the
  simulated trust domain**.

- **raVerified** — the POPO mode where the attestation evidence stands in
  for the proof-of-possession signature; the client needs only the subject
  **public** key. (Contrast: *signature POPO*, where the resident key signs
  the certificate request.)

- **POPO challenge / proof** — the RA→attester challenge
  (`KeyAttestPoPChallenge`, in `NonceResponse.responseParams`) and the
  attester→CA proof (`KeyAttestPoPProof`, cert extension), bound to the
  enrolled key.

## Verification boundary (per format)

| Format | Decode / inspect | Verify signature | Why |
|--------|------------------|------------------|-----|
| ELE dev-attest (0xDB) | yes | **yes** | layout from the public `sab_dev_attest.h` header; anchor injectable. Fully exercised in `tools/nxp_e2e_offline.py`. |
| ELE key-attest (0x74) | yes (best-effort 2GO-TLV) | **no — `NotImplementedError`** | the "signed TLV buffer" schema exists only in closed ELE firmware; NXP's own reference test treats it as a black box; no public anchor. |
| SE05x attested read | yes (tag map) | **no — `NotImplementedError`** | composition documented (AN13254) but the anchor is a per-chip factory attestation key; needs exact APDU reconstruction, not producible in simulators. |

"Inspect" means the codec can parse and pretty-print what you received.
"Verify" means the signature can be checked against a trust anchor and the
statement appraised. In the demo environment the anchor is the **simulated
trust domain** in all cases, and for 0x74/SE05x verification is not
implemented at all. `imx-secure-enclave` / RM00284 are evidence-*generation*
libraries (local primitives, no verifier, no anchor, no standard token);
this package supplies the remote-attestation layer on top.
