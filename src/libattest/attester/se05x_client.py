# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Host-side access to an NXP SE05x and the SE05x attestation Evidence provider.

The SE is reached over TCP, speaking the GlobalPlatform T=1-over-I2C block
protocol exactly as the wolfSSL SE050 simulator's ``tcp_server`` frames it:

    frame     NAD | PCB | LEN | INF (LEN bytes, at most 254) | CRC-16/X.25 (low byte first)
    NAD       0x5A host to SE, 0xA5 SE to host
    I-block   PCB = N(S) << 6 | M << 5; M marks a chained frame
    R-block   PCB = 0x80 | N(R) << 4; acknowledges a chained frame
    S-block   PCB 0xCF soft-reset request, 0xEF response carrying the ATR

The APDUs follow NXP AN12413 Rev. 2.12 (``WriteECKey`` Table 94, ``WriteBinary``
Table 97, ``ReadObject`` Table 105, ``DeleteSecureObject`` Table 123,
``ECDSASign`` Table 150, ``GetTimestamp`` Table 265). The attested read comes
from :mod:`libattest.formats.se05x.apdu`, which owns that wire format.

:class:`Se05xAttestProvider` turns one attested read into an :class:`AttestResult`.
For CMP, the key the SE generated can also sign the CSR through
:meth:`Se05xClient.sign_digest`, so its private part never leaves the SE.
"""

from __future__ import annotations

import socket
from pathlib import Path
from types import TracebackType

from libattest import get_oid_for_stmt_name
from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE
from libattest.formats.se05x.apdu import (
    ALGO_ECDSA_SHA256,
    FRESHNESS_LEN,
    TAG_1,
    TAG_2,
    TAG_3,
    TAG_4,
    build_attested_read,
    decode_tlvs,
    encode_tlv,
    recorded_command,
)
from libattest.formats.se05x.structures import encode_se05x_attest_evidence
from libattest.types import AttestResult

_NAD_HOST_TO_SE = 0x5A
_NAD_SE_TO_HOST = 0xA5
_PCB_SOFT_RESET_REQUEST = 0xCF
_PCB_SOFT_RESET_RESPONSE = 0xEF
_PCB_R_BLOCK = 0x80
_M_BIT = 0x20
# ponytail: IFSC fixed at the simulator's 254; read it from the ATR for a chip that advertises less.
_IFSC = 254

_SW_OK = 0x9000
_SELECT_APPLET = bytes.fromhex("00A4040010" + "A0000003965453000000010300000000" + "00")  # IoT applet AID
_READ_OBJECT = bytes.fromhex("80020000")  # INS_READ, P1_DEFAULT, P2_DEFAULT
_WRITE_EC_KEY_PAIR = bytes.fromhex("80016100")  # INS_WRITE, P1_KEY_PAIR | P1_EC
_WRITE_BINARY = bytes.fromhex("80010600")  # INS_WRITE, P1_BINARY
_DELETE_OBJECT = bytes.fromhex("80040028")  # INS_MGMT, P2_DELETE_OBJECT
_GET_TIMESTAMP = bytes.fromhex("8004003D")  # INS_MGMT, P2_TIME
_ECDSA_SIGN = bytes.fromhex("80030C09")  # INS_CRYPTO, P1_SIGNATURE, P2_SIGN
_TAG_POLICY = 0x11
_CURVE_NIST_P256 = 0x03  # AN12413 Table 37
_MAX_FILE_LEN = 0x7FFF  # AN12413 Table 97
_SHA256_LEN = 32


def _crc16_x25(data: bytes) -> int:
    """Return the CRC-16/X.25 of *data* (reflected 0x1021, init and final XOR 0xFFFF).

    ``binascii.crc_hqx`` is the unreflected XMODEM variant and does not match.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def _command(header: bytes, data: bytes = b"", *, le: bool = False) -> bytes:
    """Build an ISO 7816-4 command APDU.

    A command that sends data and expects a response gets an extended Lc and the
    extended Le ``00 00`` (as NXP's middleware sends ``ReadObject``), so a
    response longer than 256 bytes fits. A command without a response uses a
    short Lc unless its data exceed 255 bytes. NXP's middleware differs in two
    places the simulator accepts either way: it sends ``ECDSASign`` with a short
    Lc and no Le, and 255 bytes of data with an extended Lc.
    """
    if not data:
        return header + (b"\x00" if le else b"")
    if le or len(data) > 0xFF:
        return header + b"\x00" + len(data).to_bytes(2, "big") + data + (b"\x00\x00" if le else b"")
    return header + bytes((len(data),)) + data


class Se05xError(Exception):
    """An SE05x command ended with a status word other than ``9000``.

    Attributes
    ----------
    sw:
        The status word, e.g. ``0x6985`` (conditions not satisfied).

    """

    def __init__(self, sw: int, command: str = "") -> None:
        """Record *sw*; *command* names the failed command in the message."""
        self.sw = sw
        super().__init__(f"{command or 'SE05x command'} failed with SW {sw:04X}")


class T1Transport:
    """T=1 block transport to an SE05x over TCP, as the SE050 simulator speaks it.

    Connecting performs a soft reset; its ATR is kept in :attr:`atr`. Transport
    faults (bad CRC or NAD, unexpected block, closed connection) raise
    :class:`OSError`: a T=1 session cannot recover from them, so reconnect.
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        """Connect to *host*:*port* and soft-reset the link."""
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._rfile = self._sock.makefile("rb")
        self._send_seq = 0  # N(S) of the next I-block to the SE
        self._recv_seq = 0  # N(S) expected on the next I-block from the SE
        try:
            self.atr = self.soft_reset()
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        """Close the connection."""
        self._rfile.close()
        self._sock.close()

    def _write_frame(self, pcb: int, inf: bytes) -> None:
        frame = bytes((_NAD_HOST_TO_SE, pcb, len(inf))) + inf
        self._sock.sendall(frame + _crc16_x25(frame).to_bytes(2, "little"))

    def _read_exact(self, length: int) -> bytes:
        data = self._rfile.read(length)
        if len(data) != length:
            raise ConnectionError("T=1: the SE closed the connection")
        return data

    def _read_frame(self) -> tuple[int, bytes]:
        header = self._read_exact(3)
        body = self._read_exact(header[2] + 2)
        inf = body[:-2]
        if header[0] != _NAD_SE_TO_HOST:
            raise OSError(f"T=1: unexpected NAD {header[0]:02X}")
        if _crc16_x25(header + inf) != int.from_bytes(body[-2:], "little"):
            raise OSError("T=1: CRC mismatch on a frame from the SE")
        return header[1], inf

    def soft_reset(self) -> bytes:
        """Reset the block sequence numbers and return the SE's ATR."""
        self._write_frame(_PCB_SOFT_RESET_REQUEST, b"")
        pcb, atr = self._read_frame()
        if pcb != _PCB_SOFT_RESET_RESPONSE:
            raise OSError(f"T=1: expected the soft-reset response, got PCB {pcb:02X}")
        self._send_seq = self._recv_seq = 0
        return atr

    def transceive(self, apdu: bytes) -> tuple[bytes, int]:
        """Send one command APDU and return ``(response data, status word)``.

        Commands and responses longer than one frame are chained: every chained
        frame is acknowledged with an R-block before the next one is sent.

        Raises
        ------
        ValueError
            If *apdu* is empty.

        """
        # ponytail: no retransmission or WTX handling; TCP to the simulator never needs them.
        if not apdu:
            raise ValueError("T=1: an empty APDU sends no frame, so no response would come")
        chunks = [apdu[offset : offset + _IFSC] for offset in range(0, len(apdu), _IFSC)]
        for index, chunk in enumerate(chunks):
            more = index < len(chunks) - 1
            self._write_frame(self._send_seq << 6 | (_M_BIT if more else 0), chunk)
            self._send_seq ^= 1
            if more:
                pcb, _ = self._read_frame()
                if pcb != _PCB_R_BLOCK | self._send_seq << 4:
                    raise OSError(f"T=1: expected an R-block for the chained command, got PCB {pcb:02X}")
        response = b""
        while True:
            pcb, inf = self._read_frame()
            if pcb & ~_M_BIT != self._recv_seq << 6:
                raise OSError(f"T=1: expected an I-block with N(S)={self._recv_seq}, got PCB {pcb:02X}")
            self._recv_seq ^= 1
            response += inf
            if not pcb & _M_BIT:
                break
            self._write_frame(_PCB_R_BLOCK | self._recv_seq << 4, b"")
        if len(response) < 2:
            raise OSError("T=1: response shorter than a status word")
        return response[:-2], int.from_bytes(response[-2:], "big")


class Se05xClient:
    """The SE05x IoT-applet commands libattest needs, over :class:`T1Transport`.

    Use it as a context manager; call :meth:`select` before any other command.
    Object ids are 32-bit integers. Every status word other than ``9000`` raises
    :class:`Se05xError`.
    """

    def __init__(self, host: str, port: int) -> None:
        """Connect to the SE at *host*:*port*."""
        self._t1 = T1Transport(host, port)

    def __enter__(self) -> Se05xClient:
        """Return the client."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the connection."""
        self.close()

    def close(self) -> None:
        """Close the connection."""
        self._t1.close()

    def _call(self, command: str, apdu: bytes) -> bytes:
        data, sw = self._t1.transceive(apdu)
        if sw != _SW_OK:
            raise Se05xError(sw, command)
        return data

    def _call_tag1(self, command: str, header: bytes, data: bytes = b"") -> bytes:
        body = self._call(command, _command(header, data, le=True))
        tlvs = decode_tlvs(body)
        if [tag for tag, _ in tlvs] != [TAG_1]:
            raise ValueError(f"{command}: expected one TAG_1 in the response, got {body.hex()}")
        return tlvs[0][1]

    def select(self) -> bytes:
        """Select the IoT applet and return its version bytes."""
        return self._call("SELECT", _SELECT_APPLET)

    def read_object(self, object_id: int) -> bytes:
        """Return the value of *object_id*: a key pair's 65-byte public point, or a whole binary file."""
        return self._call_tag1("ReadObject", _READ_OBJECT, encode_tlv(TAG_1, object_id.to_bytes(4, "big")))

    def write_binary(self, object_id: int, data: bytes) -> None:
        """Create the binary file *object_id* holding *data*.

        The file must not exist yet; delete it first to replace it. A command over
        255 bytes goes out with an extended Lc and is chained over T=1.

        Raises
        ------
        ValueError
            If *data* is empty or longer than 0x7FFF bytes, the SE's file size limit.

        """
        if not 0 < len(data) <= _MAX_FILE_LEN:
            raise ValueError(f"a binary file holds 1 to {_MAX_FILE_LEN} bytes, got {len(data)}")
        payload = (
            encode_tlv(TAG_1, object_id.to_bytes(4, "big"))
            + encode_tlv(TAG_3, len(data).to_bytes(2, "big"))
            + encode_tlv(TAG_4, data)
        )
        self._call("WriteBinary", _command(_WRITE_BINARY, payload))

    def generate_ec_key(self, object_id: int, *, policy: int | None = None) -> None:
        """Generate a NIST P-256 key pair inside the SE at *object_id*.

        *policy* is an access-rule header (``POLICY_ALLOW_*`` bits OR-ed together),
        sent as one policy entry for all authentication objects:
        ``08 | 00000000 | policy``. ``None`` leaves the SE's default policy, which
        excludes attestation. A policy applies only when the object is created, so
        delete an existing object first.
        """
        payload = b""
        if policy is not None:
            payload = encode_tlv(_TAG_POLICY, b"\x08" + bytes(4) + policy.to_bytes(4, "big"))
        payload += encode_tlv(TAG_1, object_id.to_bytes(4, "big")) + encode_tlv(TAG_2, bytes((_CURVE_NIST_P256,)))
        self._call("WriteECKey", _command(_WRITE_EC_KEY_PAIR, payload))

    def delete_object(self, object_id: int) -> None:
        """Delete *object_id*."""
        self._call("DeleteSecureObject", _command(_DELETE_OBJECT, encode_tlv(TAG_1, object_id.to_bytes(4, "big"))))

    def get_timestamp(self) -> bytes:
        """Return the SE's 12-byte timestamp."""
        return self._call_tag1("GetTimestamp", _GET_TIMESTAMP)

    def attested_read(self, object_id: int, freshness: bytes) -> tuple[bytes, bytes]:
        """Read *object_id* with attestation by the SE's attestation key.

        Returns
        -------
        tuple[bytes, bytes]
            ``(recorded command, response body)``: the command without its Le, as
            the SE hashed it, and the response TLVs without the status word. These
            are the two fields of ``Se05xAttestEvidence``.

        Raises
        ------
        ValueError
            If *freshness* is not exactly 16 bytes.

        """
        apdu = build_attested_read(object_id, freshness)
        return recorded_command(apdu), self._call("attested ReadObject", apdu)

    def sign_digest(self, key_id: int, digest: bytes) -> bytes:
        """Sign a SHA-256 *digest* with the key pair *key_id*; return the DER ``Ecdsa-Sig-Value``.

        The host hashes, the SE signs (``SIG_ECDSA_SHA256``). The key's policy must
        allow signing.

        Raises
        ------
        ValueError
            If *digest* is not 32 bytes.

        """
        if len(digest) != _SHA256_LEN:
            raise ValueError(f"a SHA-256 digest is {_SHA256_LEN} bytes, got {len(digest)}")
        payload = (
            encode_tlv(TAG_1, key_id.to_bytes(4, "big"))
            + encode_tlv(TAG_2, bytes((ALGO_ECDSA_SHA256,)))
            + encode_tlv(TAG_3, digest)
        )
        return self._call_tag1("ECDSASign", _ECDSA_SIGN, payload)


class Se05xAttestProvider:
    """Evidence provider for SE05x attestation (``se05x-attest``).

    Each call reads *key_id* with attestation, using the RA nonce unchanged as the
    SE's 16-byte freshness, and returns the DER ``Se05xAttestEvidence``.

    The statement is an ASN.1 SEQUENCE. Put it into an ``AttestationBundle`` with
    ``prepare_asn1_attestation_statement(univ.ObjectIdentifier(result.oid),
    result.evidence_bytes())`` and the certificates from
    ``pem_chain_to_cmp_certs(result.cert_chain)``. Do not use
    ``AttesterClient.prepare_attestation_bundle``: it wraps the Evidence in an
    OCTET STRING.

    Parameters
    ----------
    client:
        A connected client whose applet is selected.
    key_id:
        Object id of the key pair to attest, e.g. the key the CSR certifies.
    cert_chain_pem:
        The attestation key's certificate chain, leaf first, as PEM text (``str``)
        or a PEM file (:class:`~pathlib.Path`; a ``str`` is never read as a path).

    """

    def __init__(self, client: Se05xClient, *, key_id: int, cert_chain_pem: str | Path) -> None:
        """Store the client, the attested object id and the certificate chain."""
        self._client = client
        self._key_id = key_id
        self._cert_chain = cert_chain_pem

    def generate_evidence(self, nonce: bytes | None = None) -> AttestResult:
        """Attest the key with *nonce* as the freshness.

        Raises
        ------
        ValueError
            If *nonce* is not exactly 16 bytes. The value is never padded or cut.
        Se05xError
            If the SE refuses the attested read.

        """
        if nonce is None or len(nonce) != FRESHNESS_LEN:
            got = "no nonce" if nonce is None else f"{len(nonce)} bytes"
            raise ValueError(
                f"SE05x attestation needs a {FRESHNESS_LEN}-byte nonce, got {got}; "
                f"configure the RA with NonceStore(nonce_bytes={FRESHNESS_LEN})"
            )
        command, response = self._client.attested_read(self._key_id, nonce)
        return AttestResult(
            oid=get_oid_for_stmt_name("se05x-attest"),
            evidence=encode_se05x_attest_evidence(command, response),
            media_type=SE05X_ATTESTATION_MEDIA_TYPE,
            cert_chain=self._cert_chain,
        )


__all__ = ["Se05xAttestProvider", "Se05xClient", "Se05xError", "T1Transport"]
