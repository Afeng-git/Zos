from __future__ import annotations

import os
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any


IPXE_FILES = (
    "undionly.kpxe", "ipxe.efi", "ipxe-arm64.efi", "ipxe-loongarch64.efi",
    "snponly.efi", "snponly-arm64.efi", "snponly-loongarch64.efi",
)
MAINTENANCE_FILES = (
    "x86_64/zos/bzImage", "x86_64/zos/init.xz",
    "arm64/zos/Image", "arm64/zos/init.cpio.gz",
    "loongarch64/zos/vmlinuz", "loongarch64/zos/initrd.xz",
)

_INTERFACE_CACHE: list[dict[str, str]] = []
_INTERFACE_CACHE_LOCK = threading.Lock()
_WINDOWS_INTERFACE_INDEX_CACHE: dict[str, int] = {}


def _hidden_subprocess_options() -> dict[str, Any]:
    """Keep short Windows discovery commands from opening console windows."""
    if sys.platform != "win32":
        return {}
    options: dict[str, Any] = {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
    }
    startupinfo_class = getattr(subprocess, "STARTUPINFO", None)
    if startupinfo_class is not None:
        startupinfo = startupinfo_class()
        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 1)
        startupinfo.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        options["startupinfo"] = startupinfo
    return options


def parse_dhcp_options(data: bytes) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    index = 240
    while index < len(data):
        code = data[index]; index += 1
        if code == 255: break
        if code == 0: continue
        if index >= len(data): break
        length = data[index]; index += 1
        options[code] = data[index:index + length]; index += length
    return options


def dhcp_option(code: int, value: bytes) -> bytes:
    return bytes((code, len(value))) + value


def boot_filename(architecture: int, user_class: bytes, server_ip: str, service_port: int, uefi_driver: str = "snp") -> str:
    if b"iPXE" in user_class:
        return "boot.ipxe"
    if architecture == 0:
        return "undionly.kpxe"
    if architecture in {6, 7, 9}:
        return "ipxe.efi" if uefi_driver == "native" else "snponly.efi"
    if architecture == 11:
        return "ipxe-arm64.efi" if uefi_driver == "native" else "snponly-arm64.efi"
    if architecture in {0x25, 0x27}:
        return "ipxe-loongarch64.efi" if uefi_driver == "native" else "snponly-loongarch64.efi"
    return ""


def list_ipv4_interfaces(refresh: bool = False) -> list[dict[str, str]]:
    """Return usable non-loopback IPv4 interfaces without adding dependencies."""
    if refresh and sys.platform == "win32":
        _WINDOWS_INTERFACE_INDEX_CACHE.clear()
    with _INTERFACE_CACHE_LOCK:
        if _INTERFACE_CACHE and not refresh:
            return [dict(item) for item in _INTERFACE_CACHE]
    found: list[dict[str, str]] = []
    try:
        import psutil  # type: ignore
        for name, addresses in psutil.net_if_addrs().items():
            for address in addresses:
                if address.family == socket.AF_INET and not address.address.startswith("127."):
                    found.append({"name": name, "ip": address.address, "mask": address.netmask or "255.255.255.0"})
    except (ImportError, OSError):
        pass
    if not found and sys.platform == "win32":
        command = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*' -and $_.AddressState -eq 'Preferred'} | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength | ConvertTo-Json -Compress",
        ]
        try:
            raw = subprocess.check_output(
                command, text=True, encoding="utf-8", errors="replace", timeout=5,
                **_hidden_subprocess_options(),
            ).strip()
            rows = json.loads(raw) if raw else []
            if isinstance(rows, dict): rows = [rows]
            for row in rows:
                prefix = int(row.get("PrefixLength", 24))
                mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                name = str(row.get("InterfaceAlias", "网卡"))
                found.append({"name": name, "ip": str(row["IPAddress"]), "mask": mask})
                interface_index = int(row.get("InterfaceIndex") or 0)
                if interface_index:
                    _WINDOWS_INTERFACE_INDEX_CACHE[name] = interface_index
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, json.JSONDecodeError):
            pass
    if not found and sys.platform != "win32":
        try:
            rows = json.loads(subprocess.check_output(["ip", "-j", "-4", "addr", "show"], text=True, timeout=8))
            for row in rows:
                for address in row.get("addr_info", []):
                    value = str(address.get("local", ""))
                    if address.get("scope") != "host" and value and not value.startswith("127."):
                        prefix = int(address.get("prefixlen", 24))
                        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
                        found.append({"name": str(row.get("ifname", "网卡")), "ip": value, "mask": mask})
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass
    if not found:
        try:
            values = socket.gethostbyname_ex(socket.gethostname())[2]
        except OSError:
            values = []
        for value in values:
            if not value.startswith("127."):
                found.append({"name": "系统网卡", "ip": value, "mask": "255.255.255.0"})
    unique: dict[tuple[str, str], dict[str, str]] = {}
    for item in found:
        unique[(item["name"], item["ip"])] = item
    result = sorted(unique.values(), key=lambda item: (item["name"].lower(), ipaddress.IPv4Address(item["ip"])))
    with _INTERFACE_CACHE_LOCK:
        _INTERFACE_CACHE[:] = [dict(item) for item in result]
    return result


def resolve_windows_interface_index(interface_name: str) -> int:
    """Resolve a Windows interface once and reuse it for DHCP and ProxyDHCP."""
    if sys.platform != "win32" or not interface_name:
        return 0
    cached = _WINDOWS_INTERFACE_INDEX_CACHE.get(interface_name, 0)
    if cached:
        return cached
    interface_index = 0
    try:
        interface_index = socket.if_nametoindex(interface_name)
    except (AttributeError, OSError):
        try:
            for index, name in socket.if_nameindex():
                if name == interface_name:
                    interface_index = int(index)
                    break
        except (AttributeError, OSError):
            pass
    if not interface_index:
        env = os.environ.copy()
        env["JY_PXE_INTERFACE"] = interface_name
        try:
            raw = subprocess.check_output(
                [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "(Get-NetAdapter -Name $env:JY_PXE_INTERFACE -ErrorAction Stop).ifIndex",
                ],
                text=True, encoding="utf-8", errors="replace", timeout=5, env=env,
                **_hidden_subprocess_options(),
            ).strip()
            interface_index = int(raw.splitlines()[-1])
        except (OSError, subprocess.SubprocessError, ValueError, IndexError):
            pass
    if not interface_index:
        raise RuntimeError(f"无法取得所选网卡“{interface_name}”的Windows接口编号")
    _WINDOWS_INTERFACE_INDEX_CACHE[interface_name] = interface_index
    return interface_index


def pin_windows_broadcast_interface(
    sock: socket.socket, interface_name: str, logger, service_name: str,
    interface_index: int = 0,
) -> None:
    """Force limited broadcasts out of the selected Windows interface."""
    if sys.platform != "win32" or not interface_name:
        return
    interface_index = interface_index or resolve_windows_interface_index(interface_name)
    option = getattr(socket, "IP_UNICAST_IF", 31)
    try:
        sock.setsockopt(socket.IPPROTO_IP, option, socket.htonl(interface_index))
    except OSError as exc:
        raise RuntimeError(
            f"{service_name}无法锁定到网卡“{interface_name}”(ifIndex={interface_index})：{exc}"
        ) from exc
    logger(f"{service_name}广播出口已锁定：{interface_name} (ifIndex={interface_index})")


class ProxyDhcpService:
    def __init__(self, server_ip: str, service_port: int, logger, dhcp_port: int = 67, binl_port: int = 4011, interface_name: str = "", listen_ports=None, uefi_driver: str = "snp", interface_index: int = 0):
        self.server_ip = server_ip
        self.service_port = service_port
        self.log = logger
        self.dhcp_port = dhcp_port; self.binl_port = binl_port
        self.interface_name = interface_name
        self.interface_index = interface_index
        self.uefi_driver = uefi_driver
        self.listen_ports = tuple(listen_ports) if listen_ports is not None else (dhcp_port, binl_port)
        self.stop_event = threading.Event()
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []

    def start(self):
        self.stop_event.clear()
        for port in self.listen_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            pin_windows_broadcast_interface(
                sock, self.interface_name, self.log, "ProxyDHCP", self.interface_index
            )
            if self.interface_name and hasattr(socket, "SO_BINDTODEVICE"):
                try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface_name.encode() + b"\x00")
                except OSError: self.log(f"无法将ProxyDHCP绑定到网卡 {self.interface_name}，将按服务器IP路由")
            sock.settimeout(1.0)
            try:
                sock.bind(("0.0.0.0", port))
            except OSError:
                sock.close()
                if port == self.dhcp_port: raise
                self.log("PXE端口4011未能监听，继续使用67端口")
                continue
            self.sockets.append(sock)
            thread = threading.Thread(target=self._loop, args=(sock, port), name=f"ProxyDHCP-{port}", daemon=True)
            thread.start(); self.threads.append(thread)
        ports = ",".join(str(port) for port in self.listen_ports)
        self.log(f"ProxyDHCP已启动：UDP {ports}，启动服务器 {self.server_ip}")

    def stop(self):
        self.stop_event.set()
        for sock in self.sockets:
            try: sock.close()
            except OSError: pass
        self.sockets.clear(); self.threads.clear()

    def _loop(self, sock: socket.socket, listen_port: int):
        while not self.stop_event.is_set():
            try: data, address = sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: return
            try: self._handle(sock, listen_port, data, address)
            except Exception as exc: self.log(f"ProxyDHCP请求处理失败：{exc}")

    def _handle(self, sock, listen_port: int, data: bytes, address):
        if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63": return
        options = parse_dhcp_options(data)
        vendor = options.get(60, b"")
        if b"PXEClient" not in vendor and b"iPXE" not in options.get(77, b""): return
        message_type = options.get(53, b"\x00")[0]
        if message_type not in {1, 3}: return
        architecture = struct.unpack("!H", options.get(93, b"\x00\x00")[:2].ljust(2, b"\x00"))[0]
        user_class = options.get(77, b"")
        filename = boot_filename(architecture, user_class, self.server_ip, self.service_port, self.uefi_driver)
        if not filename:
            self.log(f"忽略不支持的PXE架构代码={architecture}")
            return

        packet = bytearray(data[:240])
        packet[0] = 2
        packet[16:20] = b"\x00\x00\x00\x00"
        packet[20:24] = socket.inet_aton(self.server_ip)
        packet[44:108] = self.server_ip.encode("ascii")[:63].ljust(64, b"\x00")
        packet[108:236] = filename.encode("utf-8")[:127].ljust(128, b"\x00")
        response_type = 2 if message_type == 1 else 5
        opts = b"".join([
            dhcp_option(53, bytes((response_type,))),
            dhcp_option(54, socket.inet_aton(self.server_ip)),
            dhcp_option(60, b"PXEClient"),
            dhcp_option(66, self.server_ip.encode("ascii")),
            dhcp_option(67, filename.encode("utf-8")),
            b"\xff",
        ])
        packet = bytes(packet) + opts
        flags = struct.unpack("!H", data[10:12])[0]
        giaddr = socket.inet_ntoa(data[24:28])
        if listen_port == self.binl_port:
            destination = (address[0], address[1])
        elif giaddr != "0.0.0.0":
            destination = (giaddr, 67)
        elif flags & 0x8000 or address[0] == "0.0.0.0":
            destination = ("255.255.255.255", 68)
        else:
            destination = (address[0], 68)
        sock.sendto(packet, destination)
        mac = ":".join(f"{value:02x}" for value in data[28:34])
        self.log(f"PXE应答 {mac} 架构代码={architecture} → {filename}")


class DhcpServerService:
    """Small authoritative DHCPv4 server for an isolated imaging network."""
    def __init__(self, config: dict[str, Any], logger, interface_index: int = 0):
        self.config = config; self.log = logger
        self.server_ip = str(config["pxe_server_ip"]); self.service_port = int(config.get("service_port", 0))
        self.mask = str(config["dhcp_subnet_mask"]); self.gateway = str(config.get("dhcp_gateway", ""))
        self.dns = [
            value for value in re.split(
                r"[,，;；\s]+", str(config.get("dhcp_dns", "")).strip()
            ) if value
        ]
        self.lease_seconds = int(config.get("dhcp_lease_seconds", 28800))
        self.start_ip = ipaddress.IPv4Address(config["dhcp_pool_start"]); self.end_ip = ipaddress.IPv4Address(config["dhcp_pool_end"])
        self.interface_name = str(config.get("pxe_interface_name", "")); self.port = int(config.get("dhcp_port", 67))
        self.interface_index = interface_index
        self.uefi_driver = str(config.get("uefi_ipxe_driver", "snp"))
        self.stop_event = threading.Event(); self.socket: socket.socket | None = None; self.thread = None
        self.lock = threading.Lock(); self.leases: dict[str, tuple[str, float]] = {}
        self.client_profiles: dict[str, tuple[int, bytes]] = {}

    def start(self):
        self.stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        pin_windows_broadcast_interface(
            sock, self.interface_name, self.log, "DHCP", self.interface_index
        )
        sock.settimeout(1.0)
        if self.interface_name and hasattr(socket, "SO_BINDTODEVICE"):
            try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface_name.encode() + b"\x00")
            except OSError: self.log(f"无法将DHCP绑定到网卡 {self.interface_name}，将按服务器IP路由")
        sock.bind(("0.0.0.0", self.port)); self.socket = sock
        self.thread = threading.Thread(target=self._loop, name="DHCP-67", daemon=True); self.thread.start()
        self.log(
            f"完整DHCP已启动：{self.start_ip}-{self.end_ip}，掩码 {self.mask}，"
            f"网关 {self.gateway or '空'}，DNS {','.join(self.dns) or '空'}，"
            f"租期 {self.lease_seconds}秒"
        )

    def stop(self):
        self.stop_event.set()
        if self.socket:
            try: self.socket.close()
            except OSError: pass
        self.socket = None

    def _loop(self):
        assert self.socket is not None
        while not self.stop_event.is_set():
            try: data, address = self.socket.recvfrom(4096)
            except socket.timeout: continue
            except OSError: return
            try: self._handle(self.socket, data, address)
            except Exception as exc: self.log(f"DHCP请求处理失败：{exc}")

    def _allocate(self, mac: str, requested: str = "") -> str:
        now = time.time()
        with self.lock:
            self.leases = {key: value for key, value in self.leases.items() if value[1] > now}
            current = self.leases.get(mac)
            if current: return current[0]
            used = {value[0] for value in self.leases.values()}
            candidates: list[ipaddress.IPv4Address] = []
            if requested:
                try:
                    requested_ip = ipaddress.IPv4Address(requested)
                    if self.start_ip <= requested_ip <= self.end_ip: candidates.append(requested_ip)
                except ipaddress.AddressValueError:
                    pass
            candidates.extend(ipaddress.IPv4Address(value) for value in range(int(self.start_ip), int(self.end_ip) + 1))
            for address in candidates:
                value = str(address)
                if value not in used and value not in {self.server_ip, self.gateway}:
                    self.leases[mac] = (value, now + self.lease_seconds)
                    return value
        raise RuntimeError("DHCP地址池已用完")

    def _handle(self, sock, data: bytes, address):
        if len(data) < 240 or data[0] != 1 or data[236:240] != b"\x63\x82\x53\x63": return
        options = parse_dhcp_options(data); message_type = options.get(53, b"\x00")[0]
        if message_type not in {1, 3}: return
        server_identifier = options.get(54)
        if message_type == 3 and server_identifier and server_identifier != socket.inet_aton(self.server_ip): return
        hlen = max(1, min(16, data[2])); mac_bytes = data[28:28+hlen]
        mac = ":".join(f"{value:02x}" for value in mac_bytes)
        requested = socket.inet_ntoa(options[50]) if len(options.get(50, b"")) == 4 else ""
        if not requested and data[12:16] != b"\x00\x00\x00\x00": requested = socket.inet_ntoa(data[12:16])
        lease_ip = self._allocate(mac, requested)
        architecture_value = options.get(93, b"")
        user_class_value = options.get(77, b"")
        with self.lock:
            previous_arch, previous_user_class = self.client_profiles.get(mac, (0, b""))
            architecture = struct.unpack("!H", architecture_value[:2].ljust(2, b"\x00"))[0] if architecture_value else previous_arch
            user_class = user_class_value or previous_user_class
            self.client_profiles[mac] = (architecture, user_class)
        filename = boot_filename(architecture, user_class, self.server_ip, self.service_port, self.uefi_driver)
        packet = bytearray(240); packet[:4] = data[:4]; packet[0] = 2; packet[4:8] = data[4:8]
        packet[8:12] = data[8:12]; packet[16:20] = socket.inet_aton(lease_ip); packet[20:24] = socket.inet_aton(self.server_ip)
        packet[24:28] = data[24:28]; packet[28:44] = data[28:44]
        packet[44:108] = self.server_ip.encode("ascii")[:63].ljust(64, b"\x00")
        packet[108:236] = filename.encode("utf-8")[:127].ljust(128, b"\x00"); packet[236:240] = b"\x63\x82\x53\x63"
        response_type = 2 if message_type == 1 else 5
        reply_options = [
            dhcp_option(53, bytes((response_type,))), dhcp_option(54, socket.inet_aton(self.server_ip)),
            dhcp_option(51, struct.pack("!I", self.lease_seconds)), dhcp_option(1, socket.inet_aton(self.mask)),
            dhcp_option(28, socket.inet_aton(str(ipaddress.IPv4Network(f"{self.server_ip}/{self.mask}", strict=False).broadcast_address))),
        ]
        if filename:
            reply_options.extend([
                dhcp_option(60, b"PXEClient"),
                dhcp_option(66, self.server_ip.encode("ascii")),
                dhcp_option(67, filename.encode("utf-8")),
            ])
        if self.gateway: reply_options.append(dhcp_option(3, socket.inet_aton(self.gateway)))
        if self.dns:
            reply_options.append(
                dhcp_option(6, b"".join(socket.inet_aton(value) for value in self.dns))
            )
        reply_options.append(b"\xff")
        giaddr = socket.inet_ntoa(data[24:28])
        destination = (giaddr, 67) if giaddr != "0.0.0.0" else ("255.255.255.255", 68)
        sock.sendto(bytes(packet) + b"".join(reply_options), destination)
        boot_message = filename or f"无（不支持的架构代码={architecture}）"
        self.log(f"DHCP{'OFFER' if response_type == 2 else 'ACK'} {mac} → {lease_ip}，启动文件 {boot_message}")


class TftpService:
    def __init__(self, root: str, logger, port: int = 69):
        self.root = Path(root).resolve(); self.log = logger
        self.port = port
        self.stop_event = threading.Event(); self.socket: socket.socket | None = None; self.thread = None

    def start(self):
        self.root.mkdir(parents=True, exist_ok=True); self.stop_event.clear()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.settimeout(1.0)
        sock.bind(("0.0.0.0", self.port)); self.port = sock.getsockname()[1]; self.socket = sock
        self.thread = threading.Thread(target=self._loop, name="TFTP-69", daemon=True); self.thread.start()
        self.log(f"TFTP已启动：0.0.0.0:{self.port}，目录 {self.root}")

    def stop(self):
        self.stop_event.set()
        if self.socket:
            try: self.socket.close()
            except OSError: pass
        self.socket = None

    def _loop(self):
        assert self.socket is not None
        while not self.stop_event.is_set():
            try: data, address = self.socket.recvfrom(65535)
            except socket.timeout: continue
            except OSError: return
            if len(data) >= 4 and struct.unpack("!H", data[:2])[0] == 1:
                threading.Thread(target=self._transfer, args=(data, address), daemon=True).start()

    def _transfer(self, request: bytes, address):
        transfer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); transfer.settimeout(3.0)
        try:
            fields = request[2:].split(b"\x00")
            if len(fields) < 2: return
            filename = fields[0].decode("utf-8", "replace").replace("\\", "/").lstrip("/")
            target = (self.root / filename).resolve()
            try: target.relative_to(self.root)
            except ValueError: self._send_error(transfer, address, 2, "Access denied"); return
            if not target.is_file(): self._send_error(transfer, address, 1, "File not found"); self.log(f"TFTP文件不存在：{filename}"); return
            options = {}
            option_fields = fields[2:]
            for index in range(0, len(option_fields)-1, 2):
                if option_fields[index]: options[option_fields[index].decode("ascii", "ignore").lower()] = option_fields[index+1].decode("ascii", "ignore")
            block_size = 512; accepted = {}
            if "blksize" in options:
                block_size = max(512, min(1468, int(options["blksize"]))); accepted["blksize"] = str(block_size)
            if "tsize" in options: accepted["tsize"] = str(target.stat().st_size)
            if "timeout" in options: accepted["timeout"] = str(max(1, min(5, int(options["timeout"]))))
            if accepted:
                payload = b"".join(key.encode()+b"\x00"+value.encode()+b"\x00" for key,value in accepted.items())
                self._exchange(transfer, address, struct.pack("!H",6)+payload, 0)
            with target.open("rb") as handle:
                block = 1
                while True:
                    chunk = handle.read(block_size); packet = struct.pack("!HH",3,block)+chunk
                    self._exchange(transfer,address,packet,block)
                    if len(chunk) < block_size: break
                    block = (block + 1) & 0xffff
            self.log(f"TFTP完成 {address[0]} ← {filename} ({target.stat().st_size}字节)")
        except OSError as exc:
            if getattr(exc, "winerror", None) == 10054 or getattr(exc, "errno", None) in {10054, 104}:
                self.log(f"TFTP客户端取消了重复请求：{address[0]}")
            else:
                self.log(f"TFTP传输失败 {address[0]}：{exc}")
        except Exception as exc: self.log(f"TFTP传输失败 {address[0]}：{exc}")
        finally: transfer.close()

    @staticmethod
    def _exchange(sock, address, packet: bytes, expected_block: int):
        for _attempt in range(5):
            sock.sendto(packet,address)
            try:
                response,source = sock.recvfrom(2048)
                if source[0] == address[0] and len(response)>=4 and struct.unpack("!HH",response[:4]) == (4,expected_block): return
            except socket.timeout: continue
        raise TimeoutError(f"等待ACK {expected_block}超时")

    @staticmethod
    def _send_error(sock,address,code,message): sock.sendto(struct.pack("!HH",5,code)+message.encode()+b"\x00",address)


class PxeController:
    def __init__(self, config: dict[str, Any], config_path: str | Path | None = None):
        self.config = config; self.logs = deque(maxlen=300); self.lock = threading.Lock(); self.running = False
        self.config_path = Path(config_path).resolve() if config_path else None
        self.tftp: TftpService | None = None; self.proxy: ProxyDhcpService | None = None
        self.dhcp: DhcpServerService | None = None

    def log(self, message: str):
        with self.lock: self.logs.append(f"{time.strftime('%H:%M:%S')}  {message}")

    @staticmethod
    def interfaces() -> list[dict[str, str]]:
        return list_ipv4_interfaces(refresh=True)

    def apply_network_config(self, values: dict[str, Any]):
        if self.running: raise RuntimeError("请先停止PXE服务，再修改网络设置")
        mode = str(values.get("dhcp_mode", "proxy"))
        if mode not in {"proxy", "server"}: raise ValueError("DHCP模式无效")
        uefi_driver = str(values.get("uefi_ipxe_driver", "snp"))
        if uefi_driver not in {"snp", "native"}: raise ValueError("UEFI iPXE驱动模式无效")
        server_ip = ipaddress.IPv4Address(str(values.get("pxe_server_ip", "")))
        mask = ipaddress.IPv4Address(str(values.get("dhcp_subnet_mask", "")))
        network = ipaddress.IPv4Network(f"{server_ip}/{mask}", strict=False)
        update = {
            "pxe_interface_name": str(values.get("pxe_interface_name", "")).strip(),
            "pxe_server_ip": str(server_ip), "dhcp_mode": mode, "dhcp_subnet_mask": str(mask),
            "uefi_ipxe_driver": uefi_driver,
            "dhcp_pool_start": str(values.get("dhcp_pool_start", "")).strip(),
            "dhcp_pool_end": str(values.get("dhcp_pool_end", "")).strip(),
            "dhcp_gateway": str(values.get("dhcp_gateway", "")).strip(),
            "dhcp_dns": str(values.get("dhcp_dns", "")).strip(),
            "dhcp_lease_seconds": max(600, min(604800, int(values.get("dhcp_lease_seconds", 28800)))),
        }
        matching_interfaces = [item for item in list_ipv4_interfaces() if item["name"] == update["pxe_interface_name"]]
        if matching_interfaces and str(server_ip) not in {item["ip"] for item in matching_interfaces}:
            raise ValueError("管理端PXE地址不是所选网卡的现有地址；请重新选择网卡或使用该网卡当前IP")
        if server_ip in {network.network_address, network.broadcast_address}:
            raise ValueError("管理端PXE地址不能是子网地址或广播地址")
        if mode == "server":
            start = ipaddress.IPv4Address(update["dhcp_pool_start"]); end = ipaddress.IPv4Address(update["dhcp_pool_end"])
            if start > end: raise ValueError("DHCP地址池起始地址不能大于结束地址")
            if start not in network or end not in network: raise ValueError("DHCP地址池必须与所选网卡IP处于同一子网")
            if start in {network.network_address, network.broadcast_address} or end in {network.network_address, network.broadcast_address}:
                raise ValueError("DHCP地址池不能包含子网地址或广播地址")
            if update["dhcp_gateway"]:
                gateway = ipaddress.IPv4Address(update["dhcp_gateway"])
                if gateway not in network or gateway in {
                    network.network_address, network.broadcast_address,
                }:
                    raise ValueError("DHCP网关必须是当前子网中的可用主机地址")
            dns_values = [
                value for value in re.split(
                    r"[,，;；\s]+", update["dhcp_dns"]
                ) if value
            ]
            for value in dns_values:
                ipaddress.IPv4Address(value)
            update["dhcp_dns"] = ",".join(dns_values)
        self.config.update(update)
        if self.config_path:
            temp = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
            temp.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temp, self.config_path)
        self.log(f"网络设置已保存：{update['pxe_interface_name'] or '自动'} {server_ip}，DHCP模式 {mode}")

    def apply_capture_config(self, enabled: bool):
        self.config["capture_enabled"] = bool(enabled)
        self.config["restore_enabled"] = False
        if self.config_path:
            temp = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
            temp.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temp, self.config_path)
        state = "已启用" if enabled else "已禁用"
        self.log(f"真实镜像采集{state}；镜像还原保持禁用")

    def prepare_ipxe(self):
        root = Path(self.config["tftp_root"]); root.mkdir(parents=True,exist_ok=True)
        for filename in (*IPXE_FILES, *MAINTENANCE_FILES):
            target = root/filename
            if target.exists() and target.stat().st_size > 1024: continue
            raise RuntimeError(f"内置启动文件 {filename} 缺失；请重新解压完整安装包")
        autoexec = root/"autoexec.ipxe"
        autoexec.write_text(
            "#!ipxe\n"
            "echo Jingyun: configuring net0 by DHCP...\n"
            "ifconf --configurator dhcp --timeout 15000 net0 || goto dhcp_failed\n"
            "echo Jingyun: DHCP OK, IP=${net0/ip}, gateway=${net0/gateway}\n"
            f"chain tftp://{self.config['pxe_server_ip']}/boot.ipxe || goto tftp_failed\n"
            ":dhcp_failed\n"
            "echo Jingyun ERROR: DHCP failed. Check server PXE log, VLAN and other DHCP servers.\n"
            "ifstat\n"
            "sleep 3\n"
            "shell\n"
            ":tftp_failed\n"
            f"echo Jingyun ERROR: cannot open tftp://{self.config['pxe_server_ip']}/boot.ipxe\n"
            "route\n"
            "sleep 3\n"
            "shell\n",
            encoding="utf-8",
        )

    def start(self):
        if self.running: return
        server_ip = str(self.config.get("pxe_server_ip", ""))
        if not server_ip or server_ip == "0.0.0.0": raise RuntimeError("请在manager_config.json设置正确的pxe_server_ip")
        self.prepare_ipxe()
        self.tftp = TftpService(self.config["tftp_root"],self.log,int(self.config.get("tftp_port",69)))
        interface_name = str(self.config.get("pxe_interface_name", ""))
        interface_index = resolve_windows_interface_index(interface_name)
        mode = str(self.config.get("dhcp_mode", "proxy"))
        uefi_driver = str(self.config.get("uefi_ipxe_driver", "snp"))
        if mode == "server":
            # save_network() already validates and persists these values. Repeating
            # it here re-enumerated Windows adapters and caused a visible delay.
            self.dhcp = DhcpServerService(self.config, self.log, interface_index)
            self.proxy = ProxyDhcpService(server_ip, int(self.config.get("service_port", 0)), self.log,
                int(self.config.get("proxy_dhcp_port",67)), int(self.config.get("pxe_binl_port",4011)),
                interface_name, listen_ports=(int(self.config.get("pxe_binl_port",4011)),), uefi_driver=uefi_driver,
                interface_index=interface_index)
        else:
            self.proxy = ProxyDhcpService(server_ip,int(self.config.get("service_port", 0)),self.log,
                int(self.config.get("proxy_dhcp_port",67)),int(self.config.get("pxe_binl_port",4011)),interface_name,
                uefi_driver=uefi_driver, interface_index=interface_index)
        try:
            self.tftp.start()
            if self.dhcp: self.dhcp.start()
            self.proxy.start(); self.running = True
            label = "完整DHCP Server" if mode == "server" else "ProxyDHCP"
            self.log(f"PXE服务全部启动完成（{label}）")
        except Exception:
            self.stop(); raise

    def stop(self):
        if self.proxy: self.proxy.stop()
        if self.dhcp: self.dhcp.stop()
        if self.tftp: self.tftp.stop()
        self.proxy = None; self.dhcp = None; self.tftp = None
        if self.running: self.log("PXE服务已停止")
        self.running = False

    def status_text(self) -> str:
        state = "运行中" if self.running else "未启动"
        mode = "完整DHCP" if self.config.get("dhcp_mode") == "server" else "ProxyDHCP"
        interface = self.config.get("pxe_interface_name") or "自动"
        return f"PXE：{state}　模式：{mode}　网卡：{interface}　服务器IP：{self.config.get('pxe_server_ip')}　TFTP：{self.config.get('tftp_root')}"

    def log_text(self, reverse: bool = False) -> str:
        with self.lock:
            rows = reversed(self.logs) if reverse else self.logs
            return "\n".join(rows)
