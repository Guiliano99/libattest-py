#!/usr/bin/env python3
"""Human-readable inspection demo for the NXP OCTET STRING statement formats.

Generates a real 280-byte ELE dev-attest statement (simulator), wraps it in the
opaque ``AttestationStatement { type OID, stmt OCTET STRING }`` envelope, then
shows the three libattest.formats.nxp pretty functions doing the OID + ASN.1
parsing and rendering themselves:

    pretty_print_statement(stmt)        -> one statement
    pretty_print_stmt_bundle(bundle)    -> every statement
    log_statement_debug(stmt|bundle)    -> DEBUG log under libattest.formats.nxp

The CA/RA never inspects the inner bytes — it only routes on the OID.
"""
import logging, os, sys, subprocess, tempfile, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).with_name("src")))

from pyasn1.type import univ
from pyasn1.codec.der import encoder
from libattest.formats.csrattest.csr_attest_structures import (
    prepare_opaque_attestation_statement, prepare_attestation_bundle,
)
from libattest.formats.nxp import (
    verify_ele_dev_attest_signature,
    pretty_print_statement, pretty_print_stmt_bundle, log_statement_debug,
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
out_stmt = os.path.join(d, "stmt.bin")
subprocess.run([py, os.path.join(sim, "sim_attest.py"), "--anchor", d,
                "--nonce", "aa"*16, "--seed", "beef", "--out", out_stmt],
               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
raw = pathlib.Path(out_stmt).read_bytes()
cert = load_pem_x509_certificate(pathlib.Path(os.path.join(d, "device_attest.pem")).read_bytes())

# 2. Wrap the opaque payload in the AttestationStatement envelope (the CA/RA's
#    only view: {type OID, OCTET STRING}).
stmt = prepare_opaque_attestation_statement(univ.ObjectIdentifier(ELE_DEV_ATTEST_OID_DEFAULT), raw)
stmt_der = encoder.encode(stmt)

p("=" * 78)
p("NXP EdgeLock evidence — OCTET STRING inspection (libattest.formats.nxp)")
p("=" * 78)
p(f"raw payload               : {len(raw)} bytes  (opaque OCTET STRING)")
p(f"statement type OID        : {ELE_DEV_ATTEST_OID_DEFAULT}")
p(f"signature verify vs anchor: "
  f"{'OK' if verify_ele_dev_attest_signature(raw, cert.public_key()) else 'FAIL'}")
p()

p("-" * 78)
p("pretty_print_statement(stmt_der)   [function does OID + ASN.1 parsing]")
p("-" * 78)
p(pretty_print_statement(stmt_der))
p()

p("-" * 78)
p("pretty_print_stmt_bundle(bundle_der)   [one statement per block]")
p("-" * 78)
bundle_der = encoder.encode(prepare_attestation_bundle([stmt]))
p(pretty_print_stmt_bundle(bundle_der))
p()

p("-" * 78)
p("log_statement_debug(stmt_der, extra=...)   [DEBUG record]")
p("-" * 78)
records = []
class Cap(logging.Handler):
    def emit(self, r): records.append(r)
lg = logging.getLogger("libattest.formats.nxp")
lg.setLevel(logging.DEBUG); lg.addHandler(Cap()); lg.propagate = False
log_statement_debug(stmt_der, extra="gate=G2 tx=0x4141")
for r in records:
    p(f"[{r.levelname}] {r.name}: {r.getMessage()}")
p()
p("=> CA/RA carries only {type OID, OCTET STRING}; a verifier registered for")
p("   that OID renders the statement in the human-readable form above.")

pathlib.Path(os.path.join(d, "pretty_out.txt")).write_text("\n".join(OUT))
print(f"\n[wrote] {os.path.join(d, 'pretty_out.txt')}")
