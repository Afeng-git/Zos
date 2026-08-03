"""ZOS architecture-neutral reliable LAN multicast protocol.

The stream is divided into bounded windows.  Every receiver must acknowledge a
complete window before the sender advances, so callers can feed the compressed
image directly into zstd without storing the whole image in RAM or on disk.
"""
from __future__ import annotations

import hashlib
import socket
import struct
import time
import zlib
from pathlib import Path
from typing import Callable, Iterator


MAGIC = b"ZOSMC101"
HEADER = struct.Struct("!8s8sBIHHHI")
DATA = 1
WINDOW_END = 2
SESSION_END = 3
ACK = 4
NACK = 5
HELLO = 6
COMPLETE = 7
ERROR = 8
BEACON = 9
PAYLOAD_SIZE = 1200


class MulticastError(RuntimeError):
    pass


def normalize_mac(value: str) -> str:
    raw = value.lower().replace("-", ":")
    fields = raw.split(":")
    if len(fields) != 6 or any(len(field) != 2 for field in fields):
        raise ValueError(f"invalid MAC address: {value}")
    bytes(int(field, 16) for field in fields)
    return raw


def mac_bytes(value: str) -> bytes:
    return bytes.fromhex(normalize_mac(value).replace(":", ""))


def session_tag(session_id: str) -> bytes:
    return hashlib.sha256(session_id.encode("ascii", "strict")).digest()[:8]


def group_for_session(session_id: str) -> str:
    digest = hashlib.sha256(session_id.encode("ascii", "strict")).digest()
    return f"239.193.{1 + digest[0] % 253}.{1 + digest[1] % 253}"


def pack_packet(
    tag: bytes, kind: int, window: int = 0, sequence: int = 0,
    total: int = 0, payload: bytes = b"",
) -> bytes:
    if len(payload) > 65535:
        raise ValueError("multicast payload is too large")
    return HEADER.pack(
        MAGIC, tag, kind, window, sequence, total, len(payload),
        zlib.crc32(payload) & 0xFFFFFFFF,
    ) + payload


def unpack_packet(packet: bytes, tag: bytes) -> tuple[int, int, int, int, bytes] | None:
    if len(packet) < HEADER.size:
        return None
    magic, packet_tag, kind, window, sequence, total, length, checksum = HEADER.unpack(
        packet[:HEADER.size]
    )
    payload = packet[HEADER.size:]
    if magic != MAGIC or packet_tag != tag or length != len(payload):
        return None
    if zlib.crc32(payload) & 0xFFFFFFFF != checksum:
        return None
    return kind, window, sequence, total, payload


def _profile(profile: str) -> tuple[int, float, float]:
    return {
        "compatible": (64, 0.001, 0.8),
        "gigabit": (128, 0.0, 0.35),
        "maximum": (160, 0.0, 0.25),
    }.get(profile, (128, 0.0, 0.35))


def send_file(
    image_path: Path, session_id: str, server_ip: str, data_port: int,
    expected_macs: list[str], profile: str = "gigabit", start_timeout: int = 900,
    cancel_event=None, state_callback: Callable[[str], None] | None = None,
) -> None:
    """Reliably multicast one compressed file to every expected receiver."""
    tag = session_tag(session_id)
    group = group_for_session(session_id)
    expected = {mac_bytes(value) for value in expected_macs}
    if not expected:
        raise MulticastError("multicast has no expected receivers")
    packet_count, pacing, response_wait = _profile(profile)
    control_port = data_port + 1
    data_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    data_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(server_ip))
    data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    control.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    control.bind((server_ip, control_port))
    control.settimeout(0.5)
    destination = (group, data_port)

    def cancelled() -> bool:
        return bool(cancel_event is not None and cancel_event.is_set())

    def receive_response(deadline: float):
        while time.monotonic() < deadline:
            try:
                control.settimeout(max(0.01, deadline - time.monotonic()))
                packet, _address = control.recvfrom(65535)
            except socket.timeout:
                return None
            decoded = unpack_packet(packet, tag)
            if decoded is not None:
                return decoded
        return None

    try:
        connected: set[bytes] = set()
        deadline = time.monotonic() + start_timeout
        beacon = pack_packet(tag, BEACON)
        while connected != expected:
            if cancelled():
                raise MulticastError("multicast session was cancelled")
            if time.monotonic() >= deadline:
                missing = len(expected - connected)
                raise MulticastError(f"timed out waiting for {missing} LoongArch64 receivers")
            data_socket.sendto(beacon, destination)
            response = receive_response(time.monotonic() + 0.5)
            if response and response[0] == HELLO and response[4][:6] in expected:
                connected.add(response[4][:6])
            if state_callback:
                state_callback(f"龙芯接收器握手 {len(connected)}/{len(expected)}")

        if state_callback:
            state_callback("all_receivers_connected")
        window = 0
        file_size = image_path.stat().st_size
        digest = hashlib.sha256()
        with image_path.open("rb") as source:
            while True:
                packets: list[bytes] = []
                for _index in range(packet_count):
                    payload = source.read(PAYLOAD_SIZE)
                    if not payload:
                        break
                    digest.update(payload)
                    packets.append(payload)
                if not packets:
                    break
                acknowledged: set[bytes] = set()
                missing_sequences = set(range(len(packets)))
                window_deadline = time.monotonic() + 180
                while acknowledged != expected:
                    if cancelled():
                        raise MulticastError("multicast session was cancelled")
                    if time.monotonic() >= window_deadline:
                        raise MulticastError(
                            f"window {window} timed out; {len(expected - acknowledged)} receivers missing"
                        )
                    for sequence in sorted(missing_sequences):
                        data_socket.sendto(pack_packet(
                            tag, DATA, window, sequence, len(packets), packets[sequence]
                        ), destination)
                        if pacing and (sequence + 1) % 32 == 0:
                            time.sleep(pacing)
                    end_packet = pack_packet(tag, WINDOW_END, window, 0, len(packets))
                    for _repeat in range(2):
                        data_socket.sendto(end_packet, destination)
                    requested: set[int] = set()
                    response_deadline = time.monotonic() + response_wait
                    while time.monotonic() < response_deadline:
                        response = receive_response(response_deadline)
                        if response is None:
                            break
                        kind, response_window, _sequence, _total, payload = response
                        client = payload[:6]
                        if client not in expected or response_window != window:
                            continue
                        if kind == ACK:
                            acknowledged.add(client)
                            if acknowledged == expected:
                                break
                        elif kind == NACK and client not in acknowledged:
                            body = payload[6:]
                            requested.update(
                                struct.unpack(f"!{len(body) // 2}H", body)
                                if body and len(body) % 2 == 0 else ()
                            )
                        elif kind == ERROR:
                            raise MulticastError(payload[6:].decode("utf-8", "replace"))
                    if acknowledged != expected:
                        missing_sequences = {
                            value for value in requested if value < len(packets)
                        } or set(range(len(packets)))
                window += 1

        summary = struct.pack("!Q", file_size) + digest.digest()
        end_packet = pack_packet(tag, SESSION_END, window, payload=summary)
        completed: set[bytes] = set()
        deadline = time.monotonic() + 120
        while completed != expected:
            if cancelled():
                raise MulticastError("multicast session was cancelled")
            if time.monotonic() >= deadline:
                raise MulticastError("timed out waiting for final receiver verification")
            for _repeat in range(3):
                data_socket.sendto(end_packet, destination)
            response_deadline = time.monotonic() + 0.8
            while time.monotonic() < response_deadline:
                response = receive_response(response_deadline)
                if response is None:
                    break
                kind, _window, _sequence, _total, payload = response
                if kind == COMPLETE and payload[:6] in expected:
                    completed.add(payload[:6])
                    if completed == expected:
                        break
                elif kind == ERROR and payload[:6] in expected:
                    raise MulticastError(payload[6:].decode("utf-8", "replace"))
    finally:
        control.close()
        data_socket.close()


def receive_stream(
    session_id: str, server_ip: str, interface_ip: str, data_port: int,
    client_mac: str, receive_timeout: int = 180,
    _drop_once: set[tuple[int, int]] | None = None,
) -> Iterator[bytes]:
    """Yield verified, in-order compressed stream windows from multicast."""
    tag = session_tag(session_id)
    group = group_for_session(session_id)
    client = mac_bytes(client_mac)
    control_destination = (server_ip, data_port + 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    sock.bind(("", data_port))
    membership = socket.inet_aton(group) + socket.inet_aton(interface_ip)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
    sock.settimeout(1.0)
    current_window = 0
    chunks: dict[int, bytes] = {}
    current_total = 0
    received_bytes = 0
    digest = hashlib.sha256()
    last_packet = time.monotonic()
    last_hello = 0.0

    def reply(kind: int, window: int, payload: bytes = b"") -> None:
        sock.sendto(pack_packet(tag, kind, window, payload=client + payload), control_destination)

    try:
        while True:
            now = time.monotonic()
            if now - last_hello >= 0.5 and current_window == 0 and not chunks:
                reply(HELLO, 0)
                last_hello = now
            if now - last_packet > receive_timeout:
                raise MulticastError("multicast receive timeout")
            try:
                packet, _address = sock.recvfrom(65535)
            except socket.timeout:
                if chunks and current_total:
                    missing = [value for value in range(current_total) if value not in chunks]
                    body = struct.pack(f"!{len(missing)}H", *missing) if missing else b""
                    reply(NACK, current_window, body)
                continue
            decoded = unpack_packet(packet, tag)
            if decoded is None:
                continue
            kind, window, sequence, total, payload = decoded
            last_packet = time.monotonic()
            if kind in {BEACON}:
                reply(HELLO, current_window)
                continue
            if kind == DATA:
                if window == current_window and sequence < total:
                    key = (window, sequence)
                    if _drop_once is not None and key in _drop_once:
                        _drop_once.remove(key)
                        continue
                    current_total = total
                    chunks.setdefault(sequence, payload)
                continue
            if kind == WINDOW_END:
                if window < current_window:
                    reply(ACK, window)
                    continue
                if window != current_window:
                    continue
                current_total = total
                missing = [value for value in range(total) if value not in chunks]
                if missing:
                    reply(NACK, window, struct.pack(f"!{len(missing)}H", *missing))
                    continue
                block = b"".join(chunks[value] for value in range(total))
                digest.update(block)
                received_bytes += len(block)
                reply(ACK, window)
                current_window += 1
                chunks = {}
                current_total = 0
                yield block
                continue
            if kind == SESSION_END:
                if len(payload) != 40:
                    reply(ERROR, current_window, b"invalid final metadata")
                    raise MulticastError("invalid multicast final metadata")
                expected_size = struct.unpack("!Q", payload[:8])[0]
                expected_digest = payload[8:]
                if received_bytes != expected_size or digest.digest() != expected_digest:
                    message = (
                        f"compressed stream verification failed: {received_bytes}/{expected_size}"
                    )
                    reply(ERROR, current_window, message.encode("utf-8"))
                    raise MulticastError(message)
                for _repeat in range(3):
                    reply(COMPLETE, current_window)
                return
    finally:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, membership)
        except OSError:
            pass
        sock.close()
