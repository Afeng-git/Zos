#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server.pxe_services as pxe


pxe._WINDOWS_INTERFACE_INDEX_CACHE.clear()
with (
    patch.object(pxe.sys, "platform", "win32"),
    patch.object(pxe.socket, "if_nametoindex", side_effect=OSError),
    patch.object(pxe.socket, "if_nameindex", return_value=[]),
    patch.object(pxe.subprocess, "check_output", return_value="13\n") as command,
):
    assert pxe.resolve_windows_interface_index("Ethernet") == 13
    assert pxe.resolve_windows_interface_index("Ethernet") == 13
    assert command.call_count == 1
    assert "creationflags" in command.call_args.kwargs


class DummyService:
    created: list["DummyService"] = []

    def __init__(self, *_args, **kwargs):
        self.interface_index = kwargs.get("interface_index", 0)
        if not self.interface_index and len(_args) >= 3 and isinstance(_args[2], int):
            self.interface_index = _args[2]
        self.started = False
        self.__class__.created.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.started = False


config = {
    "tftp_root": ".", "tftp_port": 69,
    "pxe_server_ip": "192.168.5.1", "pxe_interface_name": "Ethernet",
    "dhcp_mode": "server", "dhcp_port": 67, "proxy_dhcp_port": 67,
    "pxe_binl_port": 4011, "service_port": 8090, "uefi_ipxe_driver": "snp",
}
controller = pxe.PxeController(config)
controller.prepare_ipxe = lambda: None
controller.apply_network_config = lambda *_args: (_ for _ in ()).throw(
    AssertionError("network validation must not run twice during start")
)
with (
    patch.object(pxe, "resolve_windows_interface_index", return_value=13) as resolve,
    patch.object(pxe, "TftpService", DummyService),
    patch.object(pxe, "DhcpServerService", DummyService),
    patch.object(pxe, "ProxyDhcpService", DummyService),
):
    controller.start()
    assert resolve.call_count == 1
    assert controller.running
    assert all(service.started for service in DummyService.created)
    assert all(
        service.interface_index == 13
        for service in (controller.dhcp, controller.proxy)
    )
    controller.stop()

print("fast silent PXE startup cache test passed")
