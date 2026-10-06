# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""i.MX ELE device-attest statement codec (``hsm_dev_attest``, SAB 0xDB).

Parses the fixed 280-byte ``sab_cmd_dev_attest_rsp_w_data_v2`` little-endian C
struct exactly as laid out by ``imx-secure-enclave``
(``src/common/sab_msg/include/sab_dev_attest.h`` @ 46384506, branch
``lf-6.18.37-2.1.0``) and NXP RM00284 Rev. 4.5 §3.12.

Layout (little-endian, C offsets, no padding)::

    off  size  field
     0    4    sab_mu_hdr   ver, size, command, tag
     4    4    rsp_code     (u32) 0x00000000 on success
     8   92    dev_info     cmd,ver,length, soc_id, soc_rev, lmda_val,
                            ssm_state, reserved, uid[16],
                            sha_rom_patch[32], sha_fw[32]
   100  68    dev_addn_info oem_srkh[64], trng, csal, imem, oem_srk_revoke
   168  16    nounce       echoed request nonce (V2)
   184  96    signature    ECDSA P-384, fixed r||s (48+48)

The attester signs ``SHA384(dev_info || dev_addn_info || nounce)`` — the
canonical buffer ``bytes[8:184]``.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils

# Generic (non-TPM / non-NXP) sign + verify is centralised in keyutils-py —
# the package's declared key-operations dependency.  We only route the raw
# ECDSA primitive through it here; the NXP-native canonical-buffer layout and
# fixed-width r||s signature are NXP-specific and stay in this module.
from keyutils_py import verify_signature

logger = logging.getLogger("libattest.formats.nxp.ele_dev_attest")

__all__ = [
    "DEV_ATTEST_SIGN_SIZE",
    "DEV_ATTEST_NOUNCE_SIZE_V1",
    "DEV_ATTEST_NOUNCE_SIZE_V2",
    "EleDevAttestStatement",
    "EleDevAttestError",
    "decode_ele_dev_attest",
    "verify_ele_dev_attest_signature",
    "canonical_signed_bytes",
]

# Constants — verbatim from sab_dev_attest.h @ 46384506.
DEV_ATTEST_SIGN_SIZE = 96
DEV_ATTEST_NOUNCE_SIZE_V1 = 4
DEV_ATTEST_NOUNCE_SIZE_V2 = 16

SAB_CMD_DEV_ATTEST = 0xDB
SAB_RSP_OK = 0x00000000

# Struct sizes (byte-exact; see layout above).
_DEV_INFO_SIZE = 92
_DEV_ADDN_INFO_SIZE = 68
_NOUNCE_OFFSET = 168
_SIG_OFFSET = 184
_STATEMENT_SIZE = 280
_CANONICAL_START = 8
_CANONICAL_END = _SIG_OFFSET  # 184

_UID_SIZE = 16
_ROM_PATCH_SHA_SIZE = 32
_FW_SHA_SIZE = 32
_OEM_SRKH_SIZE = 64


class EleDevAttestError(ValueError):
    """Raised when a dev-attest statement is structurally invalid."""


@dataclass
class EleDevAttestStatement:
    """Decoded ``sab_cmd_dev_attest_rsp_w_data_v2`` statement."""

    # header
    ver: int
    size: int
    command: int
    tag: int
    rsp_code: int
    # dev_info
    info_cmd: int
    info_ver: int
    info_length: int
    soc_id: int
    soc_rev: int
    lmda_val: int
    ssm_state: int
    reserved: int
    uid: bytes
    sha_rom_patch: bytes
    sha_fw: bytes
    # dev_addn_info
    oem_srkh: bytes
    trng_state: int
    csal_state: int
    imem_state: int
    oem_srk_revoke_status: int
    # freshness + signature
    nounce: bytes
    signature: bytes  # raw r||s (96 bytes)
    raw: bytes = field(repr=False, default=b"")

    # ── derived helpers ────────────────────────────────────────────────────
    @property
    def nounce_size(self) -> int:
        return len(self.nounce)

    @property
    def signature_valid_code(self) -> bool:
        return self.rsp_code == SAB_RSP_OK

    def r_s(self) -> tuple[bytes, bytes]:
        """Split the fixed-width signature into (r, s)."""
        half = len(self.signature) // 2
        return self.signature[:half], self.signature[half:]

    def verify_signature(self, pubkey: ec.EllipticCurvePublicKey) -> bool:
        """Verify the statement's ECDSA signature over the canonical bytes.

        Reconstructs the DER ``r||s`` from the fixed-width field and checks it
        against ``SHA384(dev_info || dev_addn_info || nounce)``.
        """
        return verify_ele_dev_attest_signature(self, pubkey)

    def pretty(self) -> str:
        """Human-readable, single-block prettyPrint of the statement."""
        return pretty_print_ele_dev_attest(self)


def canonical_signed_bytes(stmt: EleDevAttestStatement | bytes) -> bytes:
    """Return the attester-signed canonical buffer (bytes[8:184]).

    Accepts a raw 280-byte statement or a decoded :class:`EleDevAttestStatement`.
    """
    if isinstance(stmt, bytes):
        if len(stmt) != _STATEMENT_SIZE:
            raise EleDevAttestError(
                f"statement must be {_STATEMENT_SIZE} bytes, got {len(stmt)}"
            )
        return stmt[_CANONICAL_START:_CANONICAL_END]
    return bytes([
        *struct.pack(
            "<BBHHHHBB",
            stmt.info_cmd,
            stmt.info_ver,
            stmt.info_length,
            stmt.soc_id,
            stmt.soc_rev,
            stmt.lmda_val,
            stmt.ssm_state,
            stmt.reserved,
        ),
        *stmt.uid,
        *stmt.sha_rom_patch,
        *stmt.sha_fw,
        *stmt.oem_srkh,
        *struct.pack("<BBBB", stmt.trng_state, stmt.csal_state, stmt.imem_state, stmt.oem_srk_revoke_status),
        *stmt.nounce,
    ])


def verify_ele_dev_attest_signature(
    stmt: EleDevAttestStatement | bytes, pubkey: ec.EllipticCurvePublicKey
) -> bool:
    """Verify the statement ECDSA signature (SHA-384) against *pubkey*."""
    canonical = canonical_signed_bytes(stmt)
    raw = stmt.signature if isinstance(stmt, EleDevAttestStatement) else stmt[_SIG_OFFSET : _SIG_OFFSET + DEV_ATTEST_SIGN_SIZE]
    if len(raw) != DEV_ATTEST_SIGN_SIZE:
        raise EleDevAttestError(f"signature must be {DEV_ATTEST_SIGN_SIZE} bytes, got {len(raw)}")
    r = int.from_bytes(raw[:48], "big")
    s = int.from_bytes(raw[48:], "big")
    der = ec_utils.encode_dss_signature(r, s)
    # The attester signs SHA384 over the canonical buffer; the raw bytes are
    # passed and the ECDSA primitive hashes them (matches sim_attest.py's sign
    # side).  The generic ECDSA verify is centralised in keyutils-py.
    try:
        verify_signature(pubkey, der, canonical, hash_alg="sha384")
        return True
    except InvalidSignature:
        logger.debug("ELE dev-attest signature INVALID over %dB canonical", len(canonical))
        return False


def decode_ele_dev_attest(raw: bytes) -> EleDevAttestStatement:
    """Decode a 280-byte raw dev-attest statement into a structured object.

    :raises EleDevAttestError: on a wrong length or an invalid SAB header.
    """
    if len(raw) != _STATEMENT_SIZE:
        raise EleDevAttestError(f"statement must be {_STATEMENT_SIZE} bytes, got {len(raw)}")

    ver, size, command, tag = struct.unpack_from("<BBBB", raw, 0)
    if command != SAB_CMD_DEV_ATTEST:
        logger.warning("dev-attest statement command is 0x%02X, expected 0xDB", command)
    rsp_code = struct.unpack_from("<I", raw, 4)[0]

    (
        info_cmd,
        info_ver,
        info_length,
        soc_id,
        soc_rev,
        lmda_val,
        ssm_state,
        reserved,
    ) = struct.unpack_from("<BBHHHHBB", raw, 8)
    # dev_info field offsets are ABSOLUTE: the 12-byte header (cmd..reserved)
    # occupies raw[8:20], so uid starts at 20, rom at 36, fw at 68.
    uid = raw[20 : 20 + _UID_SIZE]
    sha_rom_patch = raw[36 : 36 + _ROM_PATCH_SHA_SIZE]
    sha_fw = raw[68 : 68 + _FW_SHA_SIZE]
    oem_srkh = raw[100 : 100 + _OEM_SRKH_SIZE]
    trng_state, csal_state, imem_state, oem_srk_revoke_status = struct.unpack_from(
        "<BBBB", raw, 164
    )
    nounce = raw[_NOUNCE_OFFSET : _NOUNCE_OFFSET + DEV_ATTEST_NOUNCE_SIZE_V2]
    signature = raw[_SIG_OFFSET : _SIG_OFFSET + DEV_ATTEST_SIGN_SIZE]

    stmt = EleDevAttestStatement(
        ver=ver,
        size=size,
        command=command,
        tag=tag,
        rsp_code=rsp_code,
        info_cmd=info_cmd,
        info_ver=info_ver,
        info_length=info_length,
        soc_id=soc_id,
        soc_rev=soc_rev,
        lmda_val=lmda_val,
        ssm_state=ssm_state,
        reserved=reserved,
        uid=uid,
        sha_rom_patch=sha_rom_patch,
        sha_fw=sha_fw,
        oem_srkh=oem_srkh,
        trng_state=trng_state,
        csal_state=csal_state,
        imem_state=imem_state,
        oem_srk_revoke_status=oem_srk_revoke_status,
        nounce=nounce,
        signature=signature,
        raw=raw,
    )
    logger.debug(
        "decoded ELE dev-attest: cmd=0x%02X ver=%d soc_id=0x%04X lmda=0x%04X uid[:4]=%s",
        command, info_ver, soc_id, lmda_val, uid[:4].hex(),
    )
    return stmt


def pretty_print_ele_dev_attest(stmt: EleDevAttestStatement) -> str:
    """Render a decoded dev-attest statement as a readable block."""
    r, s = stmt.r_s()
    lines = [
        "ELE dev-attest statement (sab_cmd_dev_attest_rsp_w_data_v2, 280 B, LE)",
        f"  SAB hdr          ver={stmt.ver} size={stmt.size} cmd=0x{stmt.command:02X} tag=0x{stmt.tag:02X}",
        f"  rsp_code         0x{stmt.rsp_code:08X}"
        + ("" if stmt.signature_valid_code else "  (NON-OK)"),
        "  dev_info",
        f"    cmd/ver/len    0x{stmt.info_cmd:02X} / {stmt.info_ver} / {stmt.info_length}",
        f"    soc_id/rev     0x{stmt.soc_id:04X} / 0x{stmt.soc_rev:04X}",
        f"    lmda_val       0x{stmt.lmda_val:04X}",
        f"    ssm_state      {stmt.ssm_state}",
        f"    uid            {stmt.uid.hex()}",
        f"    sha_rom_patch  {stmt.sha_rom_patch.hex()}",
        f"    sha_fw         {stmt.sha_fw.hex()}",
        "  dev_addn_info",
        f"    oem_srkh       {stmt.oem_srkh.hex()}",
        f"    trng/csal/imem {stmt.trng_state}/{stmt.csal_state}/{stmt.imem_state}  srk_revoke={stmt.oem_srk_revoke_status}",
        "  freshness",
        f"    nounce ({stmt.nounce_size} B) {stmt.nounce.hex()}",
        "  signature (ECDSA P-384, r||s, 96 B)",
        f"    r {r.hex()}",
        f"    s {s.hex()}",
    ]
    return "\n".join(lines)
