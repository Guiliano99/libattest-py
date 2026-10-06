#!/usr/bin/env python3
"""Human-readable inspection demo for the NXP OCTET STRING statement formats.

Generates a real 280-byte ELE dev-attest statement (simulator), then shows
exactly what the CA/RA-side verifier can do with it via the libattest-py
package: OID-keyed prettyPrint (human readable) + DEBUG log, with the raw
payload carried only as an opaque OCTET STRING.
"""
import logging, os, sys, subprocess, tempfile, pathlib

# --- make the package importable (editable install already present) ---
sys.path.insert(0, str(pathlib.Path(__file__).with_name("src")))

from libattest.formats.nxp import (
    decode_ele_dev_attest, verify_ele_dev_attest_signature,
    pretty_print_nxp_statement, log_statement_debug,
    ELE_DEV_ATTEST_OID_DEFAULT,
)
from cryptography.x509 import load_pem_x509_certificate

OUT = []
def p(s=""):
    OUT.append(s); print(s)

# 1. Generate a fresh 280-byte statement via the simulator.
sim = os.environ.get("SIM_DIR", "/workspace/Projects/dockerproject/docker-projects/remote-att/imx93-ele-sim-attest")
py = sys.executable
d = tempfile.mkdtemp(prefix="nxp_pretty_")
subprocess.run([py, os.path.join(sim, "simplpki.py"), "--out", d], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
nonce_hex = "aa" * 16
out_stmt = os.path.join(d, "stmt.bin")
subprocess.run([py, os.path.join(sim, "sim_attest.py"), "--anchor", d,
                "--nonce", nonce_hex, "--seed", "beef", "--out", out_stmt],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
raw = pathlib.Path(out_stmt).read_bytes()
cert = load_pem_x509_certificate(pathlib.Path(os.path.join(d, "device_attest.pem")).read_bytes())

p("=" * 78)
p("NXP EdgeLock evidence — OCTET STRING inspection (libattest.formats.nxp)")
p("=" * 78)
p(f"raw payload               : {len(raw)} bytes  (opaque OCTET STRING)")
p(f"statement type OID        : {ELE_DEV_ATTEST_OID_DEFAULT}")
p(f"simulator nonce (RA 32B)  : {nonce_hex}  (ELE signs nonce[:16])")
p(f"signature verify vs anchor: "
  f"{'OK' if verify_ele_dev_attest_signature(raw, cert.public_key()) else 'FAIL'}")
p()

# 2. The human-readable prettyPrint (OID-keyed dispatcher — the CA/RA never
#    parses the inner bytes itself; it routes by OID and lets the codec talk).
p("-" * 78)
p("pretty_print_nxp_statement(oid, payload)  →  human readable")
p("-" * 78)
p(pretty_print_nxp_statement(ELE_DEV_ATTEST_OID_DEFAULT, raw))
p()

# 3. The DEBUG log (fire it under the libattest.formats.nxp logger at DEBUG).
p("-" * 78)
p("log_statement_debug(oid, payload, extra=...)  →  DEBUG record")
p("-" * 78)
buf = logging.getLogger()
records = []
class Cap(logging.Handler):
    def emit(self, r): records.append(r)
lg = logging.getLogger("libattest.formats.nxp")
lg.setLevel(logging.DEBUG)
lg.addHandler(Cap()); lg.propagate = False
log_statement_debug(ELE_DEV_ATTEST_OID_DEFAULT, raw, extra="gate=G2 tx=0x4141")
for r in records:
    p(f"[{r.levelname}] {r.name}: {r.getMessage()}")
p()
p("=> The CA/RA carries only {type OID, OCTET STRING}; a verifier registered")
p("   for that OID renders the statement in the human-readable form above.")

pathlib.Path(os.path.join(d, "pretty_out.txt")).write_text("\n".join(OUT))
print(f"\n[wrote] {os.path.join(d, 'pretty_out.txt')}")
