#!/usr/bin/env python3
from __future__ import annotations

import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server.pxe_services import DhcpServerService, parse_dhcp_options


class FakeSocket:
    def __init__(self):
        self.packet = b""

    def sendto(self, packet: bytes, _destination):
        self.packet = packet


def discover_packet() -> bytes:
    packet = bytearray(244)
    packet[0] = 1
    packet[1] = 1
    packet[2] = 6
    packet[4:8] = b"ZOS1"
    packet[28:34] = bytes.fromhex("000c298cff6f")
    packet[236:240] = b"\x63\x82\x53\x63"
    packet[240:244] = b"\x35\x01\x01\xff"
    return bytes(packet)


def config(gateway: str, dns: str) -> dict:
    return {
        "pxe_server_ip": "192.168.5.1",
        "service_port": 8090,
        "dhcp_subnet_mask": "255.255.255.0",
        "dhcp_gateway": gateway,
        "dhcp_dns": dns,
        "dhcp_lease_seconds": 28800,
        "dhcp_pool_start": "192.168.5.100",
        "dhcp_pool_end": "192.168.5.200",
        "pxe_interface_name": "",
        "dhcp_port": 67,
        "uefi_ipxe_driver": "snp",
    }


service = DhcpServerService(
    config("192.168.5.254", "223.6.6.6,114.114.114.114"), lambda _line: None
)
sock = FakeSocket()
service._handle(sock, discover_packet(), ("0.0.0.0", 68))
options = parse_dhcp_options(sock.packet)
assert options[3] == socket.inet_aton("192.168.5.254")
assert options[6] == (
    socket.inet_aton("223.6.6.6") + socket.inet_aton("114.114.114.114")
)

empty_service = DhcpServerService(config("", ""), lambda _line: None)
empty_sock = FakeSocket()
empty_service._handle(empty_sock, discover_packet(), ("0.0.0.0", 68))
empty_options = parse_dhcp_options(empty_sock.packet)
assert 3 not in empty_options
assert 6 not in empty_options

print("DHCP gateway and two-DNS option test passed")
