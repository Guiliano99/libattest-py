# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Offline tests for the SE05x T=1 client and the SE05x Evidence provider.

A fake SE on a socketpair answers T=1 frames the way the SE050 simulator's
``tcp_server`` does, and checks every host frame strictly: NAD, CRC, block
sequence numbers and the R-block acknowledgements of chained responses.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Callable, Iterator

import pytest

from libattest import get_oid_for_stmt_name
from libattest.attester import se05x_client
from libattest.attester.se05x_client import (
    Se05xAttestProvider,
    Se05xClient,
    Se05xError,
    T1Transport,
    _crc16_x25,
)
from libattest.formats.media_types import SE05X_ATTESTATION_MEDIA_TYPE
from libattest.formats.se05x.apdu import (
    POLICY_ALLOW_DELETE,
    POLICY_ALLOW_READ,
    POLICY_ALLOW_SIGN,
    POLICY_ALLOW_VERIFY,
    build_attested_read,
    parse_attested_read_command,
)
from libattest.formats.se05x.structures import decode_se05x_attest_evidence

# The simulator's fixed ATR (t1.rs ATR_DATA) and its soft-reset response frame,
# NAD A5, PCB EF (S-response | soft reset), LEN 35. The simulator's own unit test
# pins that frame's CRC to 87 77; the host's request frame is its 5A CF 00 37 7F.
_ATR = bytes.fromhex("00A0000003960403E800FE020B03E8080100000000640000" + "0A4A434F5034204154504F")
_ATR_FRAME = bytes.fromhex("A5EF23") + _ATR + bytes.fromhex("8777")
_SOFT_RESET_REQUEST_FRAME = bytes.fromhex("5ACF00377F")

_OK = b"\x90\x00"
_KEY_ID = 0x10AA0002
_BLOB = bytes(range(256)) * 2 + bytes(88)  # 600 bytes: three T=1 frames either way
_PEM = "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"

Respond = Callable[[bytes], bytes]


class FakeSe:
    """The SE end of a socketpair, answering T=1 frames like the simulator's ``tcp_server``.

    Every command APDU is answered with ``respond(apdu)``, which returns the
    response data followed by the status word. Any protocol violation by the host
    stops the fake and is kept in :attr:`error`.
    """

    def __init__(self, respond: Respond, atr_frame: bytes, *, bad_ack: bool = False, bad_seq: bool = False) -> None:
        """Start serving on a new socketpair.

        *bad_ack* acknowledges chained commands with the wrong N(R); *bad_seq* sends
        response I-blocks with the wrong N(S).
        """
        self.host_end, self._se_end = socket.socketpair()
        self.host_end.settimeout(5)
        self._rfile = self._se_end.makefile("rb")
        self._respond = respond
        self._atr_frame = atr_frame
        self._bad_ack = bad_ack
        self._bad_seq = bad_seq
        self.apdus: list[bytes] = []
        self.host_frames: list[bytes] = []
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def host_pcbs(self) -> list[int]:
        """Return the PCB of every frame the host sent, in order."""
        return [frame[1] for frame in self.host_frames]

    def _read_frame(self) -> tuple[int, bytes] | None:
        header = self._rfile.read(3)
        if len(header) < 3:
            return None
        body = self._rfile.read(header[2] + 2)
        assert header[0] == 0x5A, f"host NAD {header[0]:02X}"
        assert _crc16_x25(header + body[:-2]).to_bytes(2, "little") == body[-2:], "host CRC"
        self.host_frames.append(header + body)
        return header[1], body[:-2]

    def _write_frame(self, pcb: int, inf: bytes) -> None:
        frame = bytes((0xA5, pcb, len(inf))) + inf
        self._se_end.sendall(frame + _crc16_x25(frame).to_bytes(2, "little"))

    def _serve(self) -> None:
        recv_seq = send_seq = 0
        command = b""
        try:
            while (frame := self._read_frame()) is not None:
                pcb, inf = frame
                if pcb == 0xCF:
                    self._se_end.sendall(self._atr_frame)
                    recv_seq = send_seq = 0
                    continue
                assert pcb & ~0x20 == recv_seq << 6, f"host I-block PCB {pcb:02X}"
                recv_seq ^= 1
                command += inf
                if pcb & 0x20:
                    self._write_frame(0x80 | (recv_seq ^ self._bad_ack) << 4, b"")
                    continue
                self.apdus.append(command)
                response, command = self._respond(self.apdus[-1]), b""
                chunks = [response[offset : offset + 254] for offset in range(0, len(response), 254)]
                for index, chunk in enumerate(chunks):
                    more = index < len(chunks) - 1
                    self._write_frame((send_seq ^ self._bad_seq) << 6 | (0x20 if more else 0), chunk)
                    send_seq ^= 1
                    if more:
                        ack = self._read_frame()
                        assert ack is not None and ack[0] == 0x80 | send_seq << 4, "missing R-block"
        except BaseException as exc:  # reported by the fixture
            self.error = exc
        finally:
            # shutdown, not only close: the open makefile() reader would keep the socket alive.
            with contextlib.suppress(OSError):
                self._se_end.shutdown(socket.SHUT_RDWR)
            self._rfile.close()
            self._se_end.close()

    def stop(self) -> None:
        """Disconnect the host end and wait for the fake to finish."""
        with contextlib.suppress(OSError):
            self.host_end.shutdown(socket.SHUT_RDWR)
        self._thread.join(timeout=5)


def _no_command(apdu: bytes) -> bytes:
    """Fail on any command: the test expects none to be sent."""
    raise AssertionError(f"unexpected command {apdu.hex()}")


@pytest.fixture
def fake_se(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., FakeSe]]:
    """Return a factory that starts a :class:`FakeSe` and routes the next connection to it."""
    fakes: list[FakeSe] = []

    def start(
        respond: Respond = _no_command, atr_frame: bytes = _ATR_FRAME, *, bad_ack: bool = False, bad_seq: bool = False
    ) -> FakeSe:
        fake = FakeSe(respond, atr_frame, bad_ack=bad_ack, bad_seq=bad_seq)
        monkeypatch.setattr(se05x_client.socket, "create_connection", lambda address, timeout=None: fake.host_end)
        fakes.append(fake)
        return fake

    yield start
    for fake in fakes:
        fake.stop()
        assert fake.error is None, fake.error


# ── T=1 transport ────────────────────────────────────────────────────────────────


def test_crc16_x25_matches_the_simulator_vectors() -> None:
    """GIVEN the SE050 simulator's CRC test vectors WHEN computed THEN they match, low byte first."""
    assert _crc16_x25(bytes([0, 48, 95, 111, 242])) == 0x78A1
    assert _crc16_x25(_ATR_FRAME[:-2]).to_bytes(2, "little") == bytes.fromhex("8777")


def test_connect_soft_resets_and_keeps_the_atr(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN the simulator's ATR frame WHEN the transport connects THEN it sent 5A CF 00 37 7F and kept the ATR."""
    fake = fake_se()

    transport = T1Transport("se", 8050)
    transport.close()

    assert transport.atr == _ATR
    assert fake.host_frames == [_SOFT_RESET_REQUEST_FRAME]


def test_connect_rejects_a_frame_with_a_bad_crc(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN an ATR frame whose CRC is wrong WHEN the transport connects THEN OSError."""
    fake_se(atr_frame=_ATR_FRAME[:-1] + b"\x00")

    with pytest.raises(OSError, match="CRC"):
        T1Transport("se", 8050)


def test_connect_rejects_a_frame_with_another_nad(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN an ATR frame with NAD A6 and a valid CRC WHEN the transport connects THEN OSError."""
    frame = bytes.fromhex("A6EF23") + _ATR
    fake_se(atr_frame=frame + _crc16_x25(frame).to_bytes(2, "little"))

    with pytest.raises(OSError, match="NAD"):
        T1Transport("se", 8050)


def test_a_response_i_block_with_the_wrong_sequence_number_raises(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN an SE that answers with N(S)=1 where 0 is due WHEN a command runs THEN OSError, not a response."""
    fake_se(lambda apdu: _OK, bad_seq=True)

    with Se05xClient("se", 8050) as client, pytest.raises(OSError, match=r"N\(S\)"):
        client.delete_object(_KEY_ID)


def test_a_response_shorter_than_a_status_word_raises(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN a one-byte response WHEN a command runs THEN OSError."""
    fake_se(lambda apdu: b"\x90")

    with Se05xClient("se", 8050) as client, pytest.raises(OSError, match="shorter than a status word"):
        client.delete_object(_KEY_ID)


def test_read_object_reassembles_a_response_chained_over_three_frames(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN a 606-byte response WHEN read_object runs THEN the host acknowledges two frames and gets the value."""
    fake = fake_se(lambda apdu: bytes.fromhex("41820258") + _BLOB + _OK)

    with Se05xClient("se", 8050) as client:
        value = client.read_object(0xF0000013)

    assert value == _BLOB
    assert fake.apdus == [bytes.fromhex("80020000" + "000006" + "4104F0000013" + "0000")]
    assert fake.host_pcbs == [0xCF, 0x00, 0x90, 0x80]


def test_write_binary_chains_a_600_byte_file_with_an_extended_lc(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN 600 bytes WHEN write_binary runs THEN one extended-Lc APDU goes out in three chained I-blocks."""
    fake = fake_se(lambda apdu: _OK)

    with Se05xClient("se", 8050) as client:
        client.write_binary(0xF0000013, _BLOB)

    data = bytes.fromhex("4104F0000013" + "43020258" + "44820258") + _BLOB
    assert fake.apdus == [bytes.fromhex("8001060000") + len(data).to_bytes(2, "big") + data]
    assert fake.host_pcbs == [0xCF, 0x20, 0x60, 0x00]


def test_a_wrong_r_block_for_a_chained_command_raises(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN an SE that acknowledges a chained frame with the wrong N(R) WHEN write_binary runs THEN OSError."""
    fake = fake_se(lambda apdu: _OK, bad_ack=True)

    with Se05xClient("se", 8050) as client, pytest.raises(OSError, match="R-block"):
        client.write_binary(0xF0000013, _BLOB)

    assert fake.apdus == []


def test_sequence_numbers_alternate_across_commands(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN three single-frame commands WHEN sent in one session THEN N(S) alternates 0, 1, 0."""
    fake = fake_se(lambda apdu: _OK)

    with Se05xClient("se", 8050) as client:
        for _ in range(3):
            client.delete_object(_KEY_ID)

    assert fake.host_pcbs == [0xCF, 0x00, 0x40, 0x00]


# ── SE05x commands ───────────────────────────────────────────────────────────────

_DIGEST = bytes(range(32))
_DER_SIGNATURE = bytes.fromhex("3006020101020102")
_POINT = b"\x04" + bytes(range(64))


@pytest.mark.parametrize(
    ("call", "expected_apdu", "response", "expected_result"),
    [
        pytest.param(
            lambda client: client.select(),
            "00A4040010" + "A0000003965453000000010300000000" + "00",
            bytes.fromhex("070200"),
            bytes.fromhex("070200"),
            id="select",
        ),
        pytest.param(
            lambda client: client.read_object(_KEY_ID),
            "80020000" + "000006" + "410410AA0002" + "0000",
            bytes.fromhex("4141") + _POINT,
            _POINT,
            id="read_object",
        ),
        pytest.param(
            lambda client: client.generate_ec_key(
                _KEY_ID, policy=POLICY_ALLOW_READ | POLICY_ALLOW_SIGN | POLICY_ALLOW_VERIFY | POLICY_ALLOW_DELETE
            ),
            "80016100" + "14" + "1109" + "08" + "00000000" + "18240000" + "410410AA0002" + "420103",
            b"",
            None,
            id="generate_ec_key_with_policy",
        ),
        pytest.param(
            lambda client: client.generate_ec_key(_KEY_ID),
            "80016100" + "09" + "410410AA0002" + "420103",
            b"",
            None,
            id="generate_ec_key_default_policy",
        ),
        pytest.param(
            lambda client: client.delete_object(_KEY_ID),
            "80040028" + "06" + "410410AA0002",
            b"",
            None,
            id="delete_object",
        ),
        pytest.param(
            lambda client: client.get_timestamp(),
            "8004003D" + "00",
            bytes.fromhex("410C") + bytes(range(12)),
            bytes(range(12)),
            id="get_timestamp",
        ),
        pytest.param(
            lambda client: client.sign_digest(_KEY_ID, _DIGEST),
            "80030C09" + "00002B" + "410410AA0002" + "420121" + "4320" + _DIGEST.hex() + "0000",
            bytes.fromhex("4108") + _DER_SIGNATURE,
            _DER_SIGNATURE,
            id="sign_digest",
        ),
    ],
)
def test_command_sends_the_an12413_bytes_and_returns_the_value(
    fake_se: Callable[..., FakeSe],
    call: Callable[[Se05xClient], object],
    expected_apdu: str,
    response: bytes,
    expected_result: object,
) -> None:
    """GIVEN a client command WHEN it runs THEN the SE gets the AN12413 APDU and the caller the TAG_1 value."""
    fake = fake_se(lambda apdu: response + _OK)

    with Se05xClient("se", 8050) as client:
        result = call(client)

    assert fake.apdus == [bytes.fromhex(expected_apdu)]
    assert result == expected_result


def test_a_status_word_other_than_9000_raises_se05x_error(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN the SE answers 6985 WHEN a command runs THEN Se05xError carries the status word and the command."""
    fake_se(lambda apdu: b"\x69\x85")

    with Se05xClient("se", 8050) as client, pytest.raises(Se05xError, match="DeleteSecureObject.*6985") as caught:
        client.delete_object(_KEY_ID)

    assert caught.value.sw == 0x6985


def test_a_response_with_more_than_one_tlv_raises(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN a ReadObject response with TAG_1 and a second TLV WHEN read_object runs THEN ValueError."""
    fake_se(lambda apdu: bytes.fromhex("4141") + _POINT + bytes.fromhex("4201FF") + _OK)

    with Se05xClient("se", 8050) as client, pytest.raises(ValueError, match="one TAG_1"):
        client.read_object(_KEY_ID)


@pytest.mark.parametrize("length", [0, 0x8000], ids=["empty", "0x8000"])
def test_write_binary_rejects_a_size_outside_the_file_limits(fake_se: Callable[..., FakeSe], length: int) -> None:
    """GIVEN no data or more than 0x7FFF bytes WHEN write_binary runs THEN ValueError and no command is sent."""
    fake = fake_se()

    with Se05xClient("se", 8050) as client, pytest.raises(ValueError, match="1 to 32767 bytes"):
        client.write_binary(0xF0000013, bytes(length))

    assert fake.apdus == []


@pytest.mark.parametrize("length", [31, 33, 48])
def test_sign_digest_rejects_a_digest_that_is_not_32_bytes(fake_se: Callable[..., FakeSe], length: int) -> None:
    """GIVEN a digest that is not SHA-256 sized WHEN sign_digest runs THEN ValueError and no command is sent."""
    fake = fake_se()

    with Se05xClient("se", 8050) as client, pytest.raises(ValueError, match="32 bytes"):
        client.sign_digest(_KEY_ID, bytes(length))

    assert fake.apdus == []


# ── Evidence provider ────────────────────────────────────────────────────────────


@pytest.mark.parametrize("nonce", [None, bytes(15), bytes(17), bytes(32)], ids=["none", "15", "17", "32"])
def test_provider_refuses_a_nonce_that_is_not_16_bytes(fake_se: Callable[..., FakeSe], nonce: bytes | None) -> None:
    """GIVEN a nonce that is not 16 bytes WHEN Evidence is generated THEN ValueError naming the RA fix, no command."""
    fake = fake_se()

    with Se05xClient("se", 8050) as client:
        provider = Se05xAttestProvider(client, key_id=_KEY_ID, cert_chain_pem=_PEM)
        with pytest.raises(ValueError, match=r"NonceStore\(nonce_bytes=16\)"):
            provider.generate_evidence(nonce)

    assert fake.apdus == []


def test_provider_evidence_decodes_to_the_command_and_response_the_se_saw(fake_se: Callable[..., FakeSe]) -> None:
    """GIVEN an attested read WHEN Evidence is generated THEN its DER holds the command without Le and the body."""
    nonce = bytes(range(16))
    body = (
        bytes.fromhex("41820041")
        + _POINT
        + bytes.fromhex("42820012")
        + bytes(18)
        + bytes.fromhex("5208")
        + _DER_SIGNATURE
    )
    fake = fake_se(lambda apdu: body + _OK)

    with Se05xClient("se", 8050) as client:
        result = Se05xAttestProvider(client, key_id=_KEY_ID, cert_chain_pem=_PEM).generate_evidence(nonce)

    assert fake.apdus == [build_attested_read(_KEY_ID, nonce)]
    evidence = decode_se05x_attest_evidence(result.evidence_bytes())
    command = bytes(evidence["commandApdu"])
    assert command == fake.apdus[0][:-2]
    assert parse_attested_read_command(command).freshness == nonce
    assert bytes(evidence["responseBody"]) == body
    assert result.oid == get_oid_for_stmt_name("se05x-attest")
    assert result.media_type == SE05X_ATTESTATION_MEDIA_TYPE
    assert result.cert_chain == _PEM
