#!/usr/bin/python3
"""ZOS LoongArch64 imaging agent for the openEuler PXE maintenance image.

Provides registration, RAW whole-disk unicast/reliable-multicast imaging and
Linux post-deploy identity.  It avoids architecture-specific jq/socat/udpcast
dependencies by using Python already present in the openEuler initrd.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

for _module_path in ("/usr/lib/zos", str(Path(__file__).resolve().parents[2])):
    if _module_path not in sys.path:
        sys.path.insert(0, _module_path)
from zos_multicast import receive_stream

VERSION = "0.21.15"
TASK_ID = ""


def cmdline() -> dict[str, str]:
    values: dict[str, str] = {}
    for field in Path("/proc/cmdline").read_text(errors="replace").split():
        if "=" in field:
            key, value = field.split("=", 1)
            values[key] = value
    return values


ARGS = cmdline()
SERVER = ARGS.get("jy_server", "")
PORT = int(ARGS.get("jy_port", "8090") or 8090)
TOKEN = ARGS.get("jy_token", "")
MODE = ARGS.get("jy_mode", "register")
AUTOMATIC = ARGS.get("jy_auto", "0") == "1"
REQUESTED_MAC = ARGS.get("mac", "").lower().replace("-", ":")


def request(payload: dict, timeout: int = 20) -> dict:
    with socket.create_connection((SERVER, PORT), timeout=timeout) as connection:
        connection.sendall(json.dumps(payload, ensure_ascii=False).encode() + b"\n")
        line = connection.makefile("rb").readline(1024 * 1024)
    if not line:
        raise RuntimeError("manager closed the TCP connection without a response")
    response = json.loads(line.decode("utf-8", "replace"))
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "manager rejected the request"))
    return response


def report_failure(message: str) -> None:
    print(f"ERROR: {message}", flush=True)
    if TASK_ID:
        try:
            request({"op": "fail", "token": TOKEN, "task_id": TASK_ID, "message": message})
        except Exception:
            pass


def network_interfaces() -> list[Path]:
    interfaces = []
    for path in sorted(Path("/sys/class/net").glob("*")):
        if path.name == "lo":
            continue
        address = (path / "address").read_text(errors="replace").strip().lower()
        if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", address):
            interfaces.append(path)
    return interfaces


def configure_network() -> tuple[str, str, str]:
    subprocess.run(["ip", "link", "set", "lo", "up"], check=False)
    interfaces = network_interfaces()
    if REQUESTED_MAC:
        interfaces.sort(
            key=lambda path: 0 if (path / "address").read_text().strip().lower() == REQUESTED_MAC else 1
        )
    for interface in interfaces:
        name = interface.name
        mac = (interface / "address").read_text().strip().lower()
        subprocess.run(["ip", "link", "set", name, "up"], check=False)
        for _ in range(20):
            if (interface / "carrier").read_text(errors="replace").strip() == "1":
                break
            time.sleep(0.5)
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", name],
            text=True, stdout=subprocess.PIPE, check=False,
        ).stdout
        if not result:
            try:
                subprocess.run(
                    ["dhclient", "-1", "-v", name], timeout=45, check=False,
                    stdout=sys.stdout, stderr=sys.stderr,
                )
            except subprocess.TimeoutExpired:
                continue
            result = subprocess.run(
                ["ip", "-4", "-o", "addr", "show", "dev", name],
                text=True, stdout=subprocess.PIPE, check=False,
            ).stdout
        match = re.search(r"\sinet\s+(\d+\.\d+\.\d+\.\d+)/", result)
        if match:
            return name, mac, match.group(1)
    raise RuntimeError("no Ethernet interface obtained an IPv4 DHCP lease")


def physical_disks() -> list[dict]:
    disks: list[dict] = []
    excluded = re.compile(r"^(loop|ram|zram|sr|fd|dm-|md)")
    for block in sorted(Path("/sys/class/block").glob("*")):
        name = block.name
        if excluded.match(name) or (block / "partition").exists():
            continue
        device = Path("/dev") / name
        if not device.exists():
            continue
        try:
            size = int((block / "size").read_text().strip()) * 512
            read_only = (block / "ro").read_text().strip() == "1"
            removable = (block / "removable").read_text().strip() == "1"
        except (OSError, ValueError):
            continue
        partitions = sum(
            1 for child in Path("/sys/class/block").glob(f"{name}*")
            if child.name != name and (child / "partition").exists()
        )
        if size > 0 and not read_only and not removable:
            disks.append({
                "path": str(device), "size": size, "partitions": partitions,
                "model": (block / "device/model").read_text(errors="replace").strip()
                if (block / "device/model").exists() else "",
            })
    return disks


def inventory(interface: str, mac: str, ip: str) -> dict:
    return {
        "arch": "loongarch64", "system": "ZOS LoongArch64",
        "network": [{"interface": interface, "mac": mac, "ip": ip}],
        "disks": physical_disks(),
    }


def select_disk(requested: str, required_size: int = 0) -> dict:
    disks = [disk for disk in physical_disks() if int(disk["size"]) >= required_size]
    if requested and requested != "auto":
        for disk in disks:
            if disk["path"] == requested:
                return disk
        raise RuntimeError(f"requested disk {requested} is unavailable or too small")
    if not disks:
        raise RuntimeError("no eligible physical disk was detected")
    if len(disks) > 1:
        details = ", ".join(f"{disk['path']}({disk['size']} bytes)" for disk in disks)
        raise RuntimeError(f"multiple disks detected; select the target device explicitly: {details}")
    return disks[0]


def register_client(interface: str, mac: str, ip: str, inv: dict) -> None:
    print(f"Jingyun ZOS LoongArch64 registration {VERSION}")
    hostname = socket.gethostname() or "zos-loongarch"
    name = input(f"Client name [{hostname}]: ").strip() or hostname
    group_info = request({"op": "groups", "token": TOKEN})
    groups = group_info.get("groups") or ["默认组"]
    default_group = group_info.get("default_group") or groups[0]
    answer = input(f"Group [{default_group}] (Enter=default, ?=list): ").strip()
    group = default_group
    if answer == "?":
        for index, value in enumerate(groups, 1):
            print(f"  {index}) {value}")
        choice = input("Select group number [1]: ").strip() or "1"
        if choice.isdigit() and 1 <= int(choice) <= len(groups):
            group = groups[int(choice) - 1]
    response = request({
        "op": "register", "token": TOKEN, "mac": mac, "hostname": hostname,
        "name": name, "group": group, "ip": ip, "inventory": inv,
    })
    client = response.get("client") or {}
    print(f"Registration completed: {client.get('name', name)} / {group} / {ip}")
    answer = input("1) Reboot  2) Power off  Enter) Shell: ").strip()
    if answer == "1":
        subprocess.run(["systemctl", "reboot", "-f"], check=False)
    elif answer == "2":
        subprocess.run(["systemctl", "poweroff", "-f"], check=False)


def claim(mode: str, mac: str, ip: str, inv: dict) -> dict | None:
    response = request({
        "op": "claim", "token": TOKEN, "mode": mode, "automatic": AUTOMATIC,
        "mac": mac, "hostname": socket.gethostname(), "ip": ip, "inventory": inv,
    })
    return response.get("task")


def post_action(action: str) -> None:
    if action == "reboot":
        subprocess.run(["systemctl", "reboot", "-f"], check=False)
    elif action in {"poweroff", "shutdown"}:
        subprocess.run(["systemctl", "poweroff", "-f"], check=False)


def capture(task: dict, mac: str) -> None:
    global TASK_ID
    TASK_ID = str(task.get("id") or "")
    if task.get("image_type") != "raw_disk":
        raise RuntimeError("LoongArch64 supports RAW whole-disk capture only")
    disk = select_disk(str(task.get("device") or "auto"))
    print(f"Capturing {disk['path']} ({disk['size']} bytes) to task {TASK_ID}")
    header = {
        "op": "upload", "token": TOKEN, "task_id": TASK_ID, "mac": mac,
        "source_bytes": disk["size"], "device": disk["path"],
        "image_type": "raw_disk", "filesystem": "auto",
        "source_arch": "loongarch64",
    }
    connection = socket.create_connection((SERVER, PORT), timeout=20)
    connection.settimeout(None)
    connection.sendall(json.dumps(header).encode() + b"\n")
    with open(disk["path"], "rb", buffering=0) as source:
        compressor = subprocess.Popen(
            ["zstd", "-T0", "-3", "-c"], stdin=source, stdout=connection.fileno()
        )
        return_code = compressor.wait()
    if return_code:
        connection.close()
        raise RuntimeError(f"zstd capture pipeline failed ({return_code})")
    connection.shutdown(socket.SHUT_WR)
    response_line = connection.makefile("rb").readline(1024 * 1024)
    connection.close()
    response = json.loads(response_line.decode("utf-8", "replace"))
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "server did not complete the image"))
    print(f"Capture completed: {response.get('bytes', 0)} compressed bytes")
    post_action(str(task.get("post_action") or "none"))


def command_output(command: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, check=False,
        )
        return result.returncode, result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, str(error)


def _deepin_identity_values(task: dict) -> tuple[str, str, str, str, str, str]:
    apply_name = bool(task.get("apply_computer_name", task.get("apply_registered_identity")))
    name = str(task.get("identity_name") or "") if apply_name else ""
    mode = str(task.get("identity_network_mode") or "unchanged")
    if mode not in {"static", "dhcp", "unchanged"}:
        mode = "static" if task.get("apply_static_ip") else "unchanged"
    address = str(task.get("identity_ip") or "") if mode == "static" else ""
    prefix = str(int(task.get("identity_prefix") or 24))
    gateway = str(task.get("identity_gateway") or "") if mode == "static" else ""
    dns = ",".join(str(value) for value in (task.get("identity_dns") or []) if value)
    if mode != "static":
        dns = ""
    return name, mode, address, prefix, gateway, dns


def _deepin_profile_uuid(target_mac: str) -> tuple[str, str]:
    mac_hex = re.sub(r"[^0-9a-f]", "", target_mac.lower())[:12].rjust(12, "0")
    return mac_hex, f"00000000-0000-4000-8000-{mac_hex}"


def write_deepin_solid_etc_layer(etc_root: Path, task: dict, target_mac: str) -> None:
    name, mode, address, prefix, gateway, dns = _deepin_identity_values(task)
    etc_root.mkdir(parents=True, exist_ok=True)
    if name:
        (etc_root / "hostname").write_text(name + "\n", encoding="utf-8")
        hosts = etc_root / "hosts"
        # Do not create a new hosts file in an upper layer because that would
        # hide custom lower-layer entries. Update it only when already present.
        if hosts.exists():
            text = hosts.read_text(encoding="utf-8", errors="replace")
            if re.search(r"(?m)^127\.0\.1\.1\s+", text):
                text = re.sub(r"(?m)^127\.0\.1\.1.*$", f"127.0.1.1 {name}", text)
            else:
                text += f"\n127.0.1.1 {name}\n"
            hosts.write_text(text, encoding="utf-8")

    mac_hex, profile_uuid = _deepin_profile_uuid(target_mac)
    profile_id = f"ZOS-{mac_hex}"
    profile_rel = f"/etc/NetworkManager/system-connections/zos-identity-{mac_hex}.nmconnection"
    if mode in {"static", "dhcp"}:
        profile_dir = etc_root / "NetworkManager/system-connections"
        profile_dir.mkdir(parents=True, exist_ok=True)
        for old_profile in profile_dir.glob("zos-identity-*.nmconnection"):
            old_profile.unlink(missing_ok=True)
        profile = profile_dir / f"zos-identity-{mac_hex}.nmconnection"
        if mode == "static":
            if not address:
                raise ValueError("static identity has no IPv4 address")
            address1 = f"{address}/{prefix}" + (f",{gateway}" if gateway else "")
            dns_key = dns.replace(",", ";")
            if dns_key and not dns_key.endswith(";"):
                dns_key += ";"
            profile_text = f"""[connection]
id={profile_id}
uuid={profile_uuid}
type=ethernet
autoconnect=true
autoconnect-priority=999
multi-connect=0

[ethernet]
mac-address={target_mac}

[ipv4]
method=manual
address1={address1}
dns={dns_key}
ignore-auto-dns=true
may-fail=false
route-metric=10

[ipv6]
method=auto
may-fail=true
"""
        else:
            profile_text = f"""[connection]
id={profile_id}
uuid={profile_uuid}
type=ethernet
autoconnect=true
autoconnect-priority=999
multi-connect=0

[ethernet]
mac-address={target_mac}

[ipv4]
method=auto
ignore-auto-dns=false
may-fail=false
route-metric=10

[ipv6]
method=auto
may-fail=true
"""
        profile.write_text(profile_text, encoding="utf-8")
        profile.chmod(0o600)

    script = etc_root / "zos/zos-firstboot-identity.sh"
    service = etc_root / "systemd/system/zos-firstboot-identity.service"
    wants = etc_root / "systemd/system/multi-user.target.wants"
    script.parent.mkdir(parents=True, exist_ok=True)
    wants.mkdir(parents=True, exist_ok=True)
    template = r'''#!/bin/bash
set -u
NAME=@NAME@
MODE=@MODE@
ADDRESS=@ADDRESS@
PREFIX=@PREFIX@
GATEWAY=@GATEWAY@
DNS=@DNS@
TARGET_MAC=@MAC@
SERVER=@SERVER@
PORT=@PORT@
TOKEN=@TOKEN@
TASK_ID=@TASK@
PROFILE_ID=@PROFILE_ID@
PROFILE_FILE=@PROFILE_FILE@
DONE_FILE=@DONE_FILE@
LOG_FILE=@LOG_FILE@
mkdir -p /var/lib/zos
exec >>"$LOG_FILE" 2>&1
printf '%s identity start: task=%s name=%s mode=%s ip=%s/%s mac=%s\n' "$(date -Is 2>/dev/null || date)" "$TASK_ID" "$NAME" "$MODE" "$ADDRESS" "$PREFIX" "$TARGET_MAC"
report_identity() {
    local ok="$1" message="$2"
    if exec 9<>"/dev/tcp/${SERVER}/${PORT}" 2>/dev/null; then
        printf '{"op":"identity_result","token":"%s","task_id":"%s","mac":"%s","ok":%s,"message":"%s","actual_name":"%s","actual_ip":"%s"}\n' \
            "$TOKEN" "$TASK_ID" "$TARGET_MAC" "$ok" "$message" "$NAME" "$ADDRESS" >&9
        exec 9>&-; exec 9<&-
    fi
}
disable_self() {
    systemctl disable zos-firstboot-identity.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/multi-user.target.wants/zos-firstboot-identity.service
}
if [[ -f "$DONE_FILE" ]]; then disable_self; exit 0; fi
if [[ -n "$NAME" ]]; then
    printf '%s\n' "$NAME" >/etc/hostname 2>/dev/null || true
    hostnamectl set-hostname "$NAME" 2>/dev/null || hostname "$NAME" 2>/dev/null || true
fi
if [[ "$MODE" == unchanged ]]; then
    mkdir -p /var/lib/zos
    printf 'name=%s mode=%s ip=%s/%s\n' "$NAME" "$MODE" "$ADDRESS" "$PREFIX" >"$DONE_FILE"
    report_identity true "Deepin Solid computer name was applied"
    disable_self
    exit 0
fi
iface=""
for path in /sys/class/net/*; do
    [[ "${path##*/}" == lo ]] && continue
    current=$(cat "$path/address" 2>/dev/null)
    if [[ "${current,,}" == "${TARGET_MAC,,}" ]]; then iface="${path##*/}"; break; fi
done
[[ -n "$iface" ]] || iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
[[ -n "$iface" ]] || iface=$(ls /sys/class/net 2>/dev/null | awk '$1 != "lo" {print; exit}')
configured=0
failure="NetworkManager did not apply the registered identity profile"
if command -v nmcli >/dev/null 2>&1 && [[ -n "$iface" ]]; then
    nmcli connection reload >/dev/null 2>&1 || true
    [[ ! -f "$PROFILE_FILE" ]] || nmcli connection load "$PROFILE_FILE" >/dev/null 2>&1 || true
    if nmcli --wait 45 connection up "$PROFILE_ID" ifname "$iface" >/tmp/zos-identity-nmcli.log 2>&1; then
        configured=1
    else
        failure="NetworkManager profile $PROFILE_ID failed: $(tail -n 1 /tmp/zos-identity-nmcli.log 2>/dev/null)"
    fi
else
    failure="NetworkManager or the registered Ethernet interface was not available"
fi
if [[ "$configured" != 1 ]]; then report_identity false "$failure"; exit 1; fi
mkdir -p /var/lib/zos
printf 'name=%s mode=%s ip=%s/%s\n' "$NAME" "$MODE" "$ADDRESS" "$PREFIX" >"$DONE_FILE"
report_identity true "Deepin Solid name/network settings were applied"
disable_self
exit 0
'''
    replacements = {
        "@NAME@": name, "@MODE@": mode, "@ADDRESS@": address,
        "@PREFIX@": prefix, "@GATEWAY@": gateway, "@DNS@": dns,
        "@MAC@": target_mac, "@SERVER@": SERVER, "@PORT@": str(PORT),
        "@TOKEN@": TOKEN, "@TASK@": TASK_ID, "@PROFILE_ID@": profile_id,
        "@PROFILE_FILE@": profile_rel,
        "@DONE_FILE@": f"/var/lib/zos/deploy-identity-{TASK_ID}.done",
        "@LOG_FILE@": f"/var/lib/zos/deploy-identity-{TASK_ID}.log",
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, shlex.quote(value))
    script.write_text(template, encoding="utf-8")
    script.chmod(0o755)
    service.write_text(
        "[Unit]\nDescription=ZOS first boot identity configuration for Deepin Solid\n"
        "Wants=NetworkManager.service\nAfter=NetworkManager.service\n"
        "Before=network-online.target\n"
        "ConditionPathExists=/etc/zos/zos-firstboot-identity.sh\n\n"
        "[Service]\nType=oneshot\n"
        "ExecStartPre=-/sbin/restorecon /etc/zos/zos-firstboot-identity.sh\n"
        "ExecStart=/bin/bash /etc/zos/zos-firstboot-identity.sh\n"
        "TimeoutStartSec=150\nRemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    link = wants / service.name
    link.unlink(missing_ok=True)
    link.symlink_to("../zos-firstboot-identity.service")


def install_deepin_solid_overlay_tree(overlay_root: Path, task: dict, target_mac: str) -> int:
    if not overlay_root.is_dir():
        return 0
    targets: list[Path] = []
    for entry in sorted(overlay_root.glob("layer-*")):
        if entry.is_dir():
            targets.append(entry / "etc")
    for entry in sorted(overlay_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith("layer-"):
            continue
        if (entry / "etc").is_dir():
            targets.append(entry / "etc")
        if (
            (entry / "etc-upper").is_dir()
            or (entry / "etc-work").is_dir()
            or (entry / "usr-upper").is_dir()
            or re.fullmatch(r"[0-9a-fA-F]{32,64}\.[0-9]+", entry.name)
        ):
            targets.append(entry / "etc-upper")
    count = 0
    seen: set[str] = set()
    for etc_root in targets:
        key = str(etc_root)
        if key in seen:
            continue
        seen.add(key)
        write_deepin_solid_etc_layer(etc_root, task, target_mac)
        count += 1
    return count


def install_linux_identity(root: Path, task: dict, target_mac: str) -> str:
    apply_name = bool(task.get("apply_computer_name", task.get("apply_registered_identity")))
    name = str(task.get("identity_name") or "") if apply_name else ""
    mode = str(task.get("identity_network_mode") or "unchanged")
    if mode not in {"static", "dhcp", "unchanged"}:
        mode = "static" if task.get("apply_static_ip") else "unchanged"
    address = str(task.get("identity_ip") or "")
    prefix = str(int(task.get("identity_prefix") or 24))
    gateway = str(task.get("identity_gateway") or "")
    dns = ",".join(str(value) for value in (task.get("identity_dns") or []) if value)
    if name:
        (root / "etc").mkdir(parents=True, exist_ok=True)
        (root / "etc/hostname").write_text(name + "\n", encoding="utf-8")
        hosts = root / "etc/hosts"
        if hosts.exists():
            text = hosts.read_text(encoding="utf-8", errors="replace")
            if re.search(r"(?m)^127\.0\.1\.1\s+", text):
                text = re.sub(r"(?m)^127\.0\.1\.1.*$", f"127.0.1.1 {name}", text)
            else:
                text += f"\n127.0.1.1 {name}\n"
            hosts.write_text(text, encoding="utf-8")
    if mode == "unchanged":
        return f"Linux computer name {name} was written offline; network preserved"

    immutable = "/ostree/deploy/" in root.as_posix() and "/deploy/" in root.as_posix()
    script_rel = "/etc/zos/zos-firstboot-identity.sh" if immutable else "/usr/local/sbin/zos-firstboot-identity.sh"
    script = root / script_rel.lstrip("/")
    service = root / "etc/systemd/system/zos-firstboot-identity.service"
    wants = root / "etc/systemd/system/multi-user.target.wants"
    script.parent.mkdir(parents=True, exist_ok=True)
    wants.mkdir(parents=True, exist_ok=True)
    template = r'''#!/bin/bash
set -u
NAME=@NAME@
MODE=@MODE@
ADDRESS=@ADDRESS@
PREFIX=@PREFIX@
GATEWAY=@GATEWAY@
DNS=@DNS@
TARGET_MAC=@MAC@
SERVER=@SERVER@
PORT=@PORT@
TOKEN=@TOKEN@
TASK_ID=@TASK@
report_identity() {
    local ok="$1" message="$2"
    if exec 9<>"/dev/tcp/${SERVER}/${PORT}" 2>/dev/null; then
        printf '{"op":"identity_result","token":"%s","task_id":"%s","mac":"%s","ok":%s,"message":"%s","actual_name":"%s","actual_ip":"%s"}\n' \
            "$TOKEN" "$TASK_ID" "$TARGET_MAC" "$ok" "$message" "$NAME" "$ADDRESS" >&9
        exec 9>&-; exec 9<&-
    fi
}
[[ -z "$NAME" ]] || hostnamectl set-hostname "$NAME" 2>/dev/null || hostname "$NAME" 2>/dev/null || true
iface=""
for path in /sys/class/net/*; do
    [[ "${path##*/}" == lo ]] && continue
    current=$(cat "$path/address" 2>/dev/null)
    if [[ "${current,,}" == "${TARGET_MAC,,}" ]]; then iface="${path##*/}"; break; fi
done
[[ -n "$iface" ]] || iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
configured=0
failure="No supported Linux network configuration backend was found"
if command -v nmcli >/dev/null 2>&1 && [[ -n "$iface" ]]; then
    connection=$(nmcli -g GENERAL.CONNECTION device show "$iface" 2>/dev/null | head -n1)
    if [[ -z "$connection" || "$connection" == "--" ]]; then
        connection=$(nmcli -t -f NAME,TYPE connection show 2>/dev/null | awk -F: '$2=="802-3-ethernet" || $2=="ethernet" {print $1; exit}')
    fi
    if [[ -z "$connection" || "$connection" == "--" ]]; then
        connection="ZOS-$iface"
        nmcli connection add type ethernet ifname "$iface" con-name "$connection" \
            802-3-ethernet.mac-address "$TARGET_MAC" >/dev/null 2>&1 || connection=""
    fi
    if [[ -n "$connection" && "$connection" != "--" ]]; then
        if [[ "$MODE" == dhcp ]]; then
            args=(ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns "")
        else
            args=(ipv4.method manual ipv4.addresses "${ADDRESS}/${PREFIX}" ipv4.gateway "$GATEWAY" ipv4.dns "$DNS")
        fi
        nmcli connection modify "$connection" "${args[@]}" && nmcli --wait 30 connection up "$connection" && configured=1
        [[ "$configured" == 1 ]] || failure="NetworkManager rejected the requested network settings"
    else
        failure="NetworkManager has no Ethernet connection for the registered MAC"
    fi
elif [[ -d /etc/sysconfig/network-scripts && -n "$iface" ]]; then
    cfg="/etc/sysconfig/network-scripts/ifcfg-$iface"
    touch "$cfg"
    sed -i '/^\(BOOTPROTO\|IPADDR\|PREFIX\|GATEWAY\|DNS1\|DNS2\)=/d' "$cfg"
    echo "DEVICE=$iface" >>"$cfg"; echo "ONBOOT=yes" >>"$cfg"
    if [[ "$MODE" == dhcp ]]; then
        echo "BOOTPROTO=dhcp" >>"$cfg"
    else
        echo "BOOTPROTO=none" >>"$cfg"; echo "IPADDR=$ADDRESS" >>"$cfg"; echo "PREFIX=$PREFIX" >>"$cfg"
        [[ -z "$GATEWAY" ]] || echo "GATEWAY=$GATEWAY" >>"$cfg"
        [[ -z "$DNS" ]] || echo "DNS1=${DNS%%,*}" >>"$cfg"
        [[ "$DNS" != *,* ]] || echo "DNS2=${DNS#*,}" >>"$cfg"
    fi
    configured=1
elif [[ -d /etc/systemd/network && -n "$iface" ]]; then
    cfg=/etc/systemd/network/10-zos-identity.network
    { echo '[Match]'; echo "MACAddress=$TARGET_MAC"; echo; echo '[Network]';
      if [[ "$MODE" == dhcp ]]; then echo 'DHCP=yes'; else
        echo "Address=$ADDRESS/$PREFIX"; [[ -z "$GATEWAY" ]] || echo "Gateway=$GATEWAY"
        [[ -z "$DNS" ]] || echo "DNS=${DNS//,/ }"; fi; } >"$cfg"
    systemctl enable systemd-networkd.service >/dev/null 2>&1 || true
    configured=1
elif [[ -d /etc/network/interfaces.d && -n "$iface" ]]; then
    cfg=/etc/network/interfaces.d/zos-identity
    if [[ "$MODE" == dhcp ]]; then
        printf 'auto %s\niface %s inet dhcp\n' "$iface" "$iface" >"$cfg"
    else
        { echo "auto $iface"; echo "iface $iface inet static"; echo "    address $ADDRESS/$PREFIX"
          [[ -z "$GATEWAY" ]] || echo "    gateway $GATEWAY"
          [[ -z "$DNS" ]] || echo "    dns-nameservers ${DNS//,/ }"; } >"$cfg"
    fi
    configured=1
fi
if [[ "$configured" != 1 ]]; then report_identity false "$failure"; exit 1; fi
mkdir -p /var/lib/zos
echo "name=$NAME mode=$MODE ip=$ADDRESS/$PREFIX" >/var/lib/zos/deploy-identity.done
report_identity true "Linux name/network settings were applied"
systemctl disable zos-firstboot-identity.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/multi-user.target.wants/zos-firstboot-identity.service
exit 0
'''
    replacements = {
        "@NAME@": name, "@MODE@": mode, "@ADDRESS@": address,
        "@PREFIX@": prefix, "@GATEWAY@": gateway, "@DNS@": dns,
        "@MAC@": target_mac, "@SERVER@": SERVER, "@PORT@": str(PORT),
        "@TOKEN@": TOKEN, "@TASK@": TASK_ID,
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, shlex.quote(value))
    script.write_text(template, encoding="utf-8")
    script.chmod(0o755)
    service.write_text(
        "[Unit]\nDescription=ZOS first boot identity configuration\n"
        "Wants=network-online.target\nAfter=NetworkManager.service network-online.target\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart=/bin/bash {script_rel}\n"
        "TimeoutStartSec=120\nRemainAfterExit=yes\n\n"
        "[Install]\nWantedBy=multi-user.target\n",
        encoding="utf-8",
    )
    link = wants / service.name
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to("../zos-firstboot-identity.service")
    return f"Linux {mode} network identity was scheduled for first boot"


def apply_linux_identity(disk: str, task: dict, target_mac: str) -> tuple[bool, str]:
    if not task.get("apply_registered_identity"):
        return True, "identity disabled"
    subprocess.run(["blockdev", "--rereadpt", disk], check=False)
    subprocess.run(["udevadm", "settle"], check=False)
    if Path("/sbin/lvm").exists() or subprocess.run(
        ["sh", "-c", "command -v lvm >/dev/null"], check=False
    ).returncode == 0:
        command_output(["lvm", "pvscan", "--cache"], 30)
        command_output(["lvm", "vgchange", "-ay"], 30)
        subprocess.run(["udevadm", "settle"], check=False)
    base = Path(disk).name
    candidates: list[Path] = []
    for block in sorted(Path("/sys/class/block").glob(base + "*")):
        if (block / "partition").exists():
            candidates.append(Path("/dev") / block.name)
    candidates.extend(
        path for path in sorted(Path("/dev/mapper").glob("*"))
        if path.name != "control"
    )
    candidates.extend(sorted(Path("/dev").glob("md*")))
    if not candidates:
        candidates.append(Path(disk))
    mountpoint = Path("/mnt/zos-target")
    mountpoint.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = str(candidate.resolve())
        except OSError:
            resolved = str(candidate)
        if resolved in seen or not candidate.exists():
            continue
        seen.add(resolved)
        code, filesystem = command_output(["blkid", "-o", "value", "-s", "TYPE", str(candidate)], 10)
        filesystem = filesystem.strip().lower()
        if code != 0 or filesystem not in {"ext2", "ext3", "ext4", "xfs", "btrfs"}:
            continue
        subprocess.run(["umount", "-l", str(mountpoint)], check=False)
        command = ["mount", "-o", "rw", str(candidate), str(mountpoint)]
        if filesystem == "xfs":
            command = ["mount", "-t", "xfs", "-o", "rw,nouuid", str(candidate), str(mountpoint)]
        elif filesystem == "btrfs":
            command = ["mount", "-t", "btrfs", "-o", "rw,subvolid=5", str(candidate), str(mountpoint)]
        code, output = command_output(command, 25)
        if code != 0 and filesystem == "btrfs":
            code, output = command_output(
                ["mount", "-t", "btrfs", "-o", "rw", str(candidate), str(mountpoint)], 25
            )
        if code != 0:
            errors.append(f"{candidate}: {output[-120:]}")
            continue
        solid_layers = 0
        overlay_roots: list[Path] = [
            mountpoint / "overlay/data", mountpoint / "persistent/overlay/data"
        ]
        try:
            for current, directories, _files in os.walk(mountpoint):
                relative = Path(current).relative_to(mountpoint)
                if len(relative.parts) >= 6:
                    directories[:] = []
                    continue
                if Path(current).name == "overlay" and "data" in directories:
                    overlay_roots.append(Path(current) / "data")
        except OSError as error:
            errors.append(f"{candidate}: overlay scan: {error}")
        seen_overlay_roots: set[str] = set()
        for overlay_root in overlay_roots:
            overlay_key = str(overlay_root)
            if overlay_key in seen_overlay_roots:
                continue
            seen_overlay_roots.add(overlay_key)
            try:
                solid_layers += install_deepin_solid_overlay_tree(overlay_root, task, target_mac)
            except Exception as error:
                errors.append(f"{candidate}:{overlay_root}: {error}")
        if solid_layers:
            subprocess.run(["sync"], check=False)
            subprocess.run(["umount", "-l", str(mountpoint)], check=False)
            return True, (
                f"Deepin 25 Solid identity written to {solid_layers} active/lower "
                "modification layers; hostname and NetworkManager profile will be "
                "applied on first boot"
            )
        roots = [mountpoint, mountpoint / "@", mountpoint / "rootfs", mountpoint / "sysroot"]
        for base_root in (mountpoint, mountpoint / "sysroot", mountpoint / "rootfs"):
            roots.extend(sorted(base_root.glob("ostree/deploy/*/deploy/*.0")))
        applied: list[str] = []
        seen_roots: set[str] = set()
        for root in roots:
            root_key = str(root)
            if root_key in seen_roots or not root.is_dir():
                continue
            seen_roots.add(root_key)
            os_release = root / "etc/os-release"
            if not ((root / "usr/lib/os-release").exists() or os_release.exists() or os_release.is_symlink()):
                continue
            try:
                applied.append(install_linux_identity(root, task, target_mac))
            except Exception as error:
                errors.append(f"{candidate}:{root}: {error}")
        subprocess.run(["sync"], check=False)
        subprocess.run(["umount", "-l", str(mountpoint)], check=False)
        if applied:
            if len(applied) > 1:
                return True, f"Linux identity written to {len(applied)} OSTree deployments; {applied[-1]}"
            return True, applied[0]
    return False, "; ".join(errors[-3:]) or "no supported LoongArch64 Linux root partition found"

def show_written_progress(written: int, source_size: int, *, finish: bool = False) -> None:
    """Refresh one console row using MiB while retaining exact byte checks."""
    total = max(int(source_size), 1)
    current = max(0, min(int(written), total))
    percent = current * 100.0 / total
    print(
        f"Written {current / 1024 / 1024:.1f}/"
        f"{total / 1024 / 1024:.1f} MiB ({percent:.1f}%)",
        end="\n" if finish else "\r",
        flush=True,
    )


def deploy(task: dict, mac: str, interface: str, interface_ip: str) -> None:
    global TASK_ID
    TASK_ID = str(task.get("id") or "")
    if task.get("image_type") != "raw_disk":
        raise RuntimeError("LoongArch64 deploys RAW whole-disk images only")
    source_arch = str(task.get("source_arch") or "unknown")
    if source_arch not in {"unknown", "loongarch64", "loong64"}:
        raise RuntimeError(f"image architecture {source_arch} cannot boot on LoongArch64")
    transfer_mode = str(task.get("transfer_mode") or "unicast")
    if transfer_mode not in {"unicast", "multicast"}:
        raise RuntimeError(f"unsupported transfer mode: {transfer_mode}")
    source_size = int(task.get("source_bytes") or 0)
    disk = select_disk(str(task.get("device") or "auto"), source_size)
    print(f"Task {TASK_ID}: {task.get('image_name', 'image')} -> {disk['path']}")
    print("WARNING: every partition and all data on the target disk will be overwritten.")
    for count in range(5, 0, -1):
        print(f"Writing starts in {count}...", flush=True)
        time.sleep(1)
    connection = None
    if transfer_mode == "multicast":
        print("Target ready. Waiting for every LoongArch64 group client...")
        response = request({
            "op": "multicast_ready", "token": TOKEN, "task_id": TASK_ID, "mac": mac,
        })
        while True:
            state = str(response.get("state") or "waiting")
            print(
                f"Multicast ready {response.get('ready_count', 0)}/"
                f"{response.get('expected', 0)}; state={state}", flush=True,
            )
            if state in {"failed", "cancelled"}:
                raise RuntimeError(f"multicast session {state}")
            if response.get("protocol") == "zosmc1" and state in {"starting", "running"}:
                break
            time.sleep(2)
            response = request({
                "op": "multicast_status", "token": TOKEN,
                "task_id": TASK_ID, "mac": mac,
            })
        portbase = int(response.get("portbase") or 0)
        session_id = str(task.get("multicast_session_id") or "")
        if portbase < 1024 or not session_id:
            raise RuntimeError("manager returned invalid ZOS multicast parameters")
        request({"op": "deploy_started", "token": TOKEN, "task_id": TASK_ID, "mac": mac})
        decompressor = subprocess.Popen(
            ["zstd", "-d", "-c"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        assert decompressor.stdin is not None and decompressor.stdout is not None
        write_state: dict[str, object] = {"written": 0, "error": None}

        def disk_writer() -> None:
            last_report = 0.0
            try:
                with open(disk["path"], "wb", buffering=0) as target:
                    while True:
                        block = decompressor.stdout.read(8 * 1024 * 1024)
                        if not block:
                            break
                        target.write(block)
                        write_state["written"] = int(write_state["written"]) + len(block)
                        now = time.monotonic()
                        if now - last_report >= 1:
                            current = int(write_state["written"])
                            show_written_progress(current, source_size)
                            try:
                                request({
                                    "op": "deploy_progress", "token": TOKEN,
                                    "task_id": TASK_ID, "mac": mac,
                                    "written_bytes": current,
                                })
                            except Exception:
                                pass
                            last_report = now
                    os.fsync(target.fileno())
            except Exception as error:
                write_state["error"] = error

        writer = threading.Thread(target=disk_writer, name="zos-loong-disk-writer", daemon=True)
        writer.start()
        try:
            for compressed_window in receive_stream(
                session_id=session_id, server_ip=SERVER, interface_ip=interface_ip,
                data_port=portbase, client_mac=mac, receive_timeout=180,
            ):
                if write_state["error"]:
                    raise RuntimeError(str(write_state["error"]))
                decompressor.stdin.write(compressed_window)
            decompressor.stdin.close()
            writer.join(timeout=300)
        except Exception:
            decompressor.kill()
            raise
        if writer.is_alive():
            decompressor.kill()
            raise RuntimeError("timed out flushing the deployed disk")
        written = int(write_state["written"])
        if write_state["error"]:
            raise RuntimeError(str(write_state["error"]))
    else:
        request({"op": "deploy_started", "token": TOKEN, "task_id": TASK_ID, "mac": mac})
        connection = socket.create_connection((SERVER, PORT), timeout=20)
        connection.settimeout(None)
        connection.sendall(json.dumps({
            "op": "download", "token": TOKEN, "task_id": TASK_ID, "mac": mac,
        }).encode() + b"\n")
        decompressor = subprocess.Popen(
            ["zstd", "-d", "-c"], stdin=connection.makefile("rb", buffering=0),
            stdout=subprocess.PIPE,
        )
        written = 0
        last_report = 0.0
        assert decompressor.stdout is not None
        with open(disk["path"], "wb", buffering=0) as target:
            while True:
                block = decompressor.stdout.read(8 * 1024 * 1024)
                if not block:
                    break
                target.write(block)
                written += len(block)
                now = time.monotonic()
                if now - last_report >= 1:
                    show_written_progress(written, source_size)
                    try:
                        request({
                            "op": "deploy_progress", "token": TOKEN, "task_id": TASK_ID,
                            "mac": mac, "written_bytes": written,
                        })
                    except Exception:
                        pass
                    last_report = now
            os.fsync(target.fileno())
        connection.close()
    show_written_progress(written, source_size, finish=True)
    if decompressor.wait() != 0 or written != source_size:
        raise RuntimeError(f"image pipeline failed or size mismatched ({written}/{source_size})")
    identity_ok, message = apply_linux_identity(disk["path"], task, mac)
    request({
        "op": "complete", "token": TOKEN, "task_id": TASK_ID, "mac": mac,
        "identity_ok": identity_ok, "identity_message": message,
    })
    print("Image deployment completed and flushed to disk.")
    post_action(str(task.get("post_action") or "none"))


def main() -> int:
    print(f"Jingyun ZOS LoongArch64 maintenance agent {VERSION}")
    print("Official openEuler 24.03 LTS kernel/initrd test environment")
    if not SERVER or not TOKEN:
        print("ERROR: missing jy_server or jy_token kernel parameter")
        return 1
    try:
        interface, mac, ip = configure_network()
        print(f"Network ready: {interface} {mac} {ip}; manager {SERVER}:{PORT}")
        inv = inventory(interface, mac, ip)
        for disk in inv["disks"]:
            print(f"Disk: {disk['path']} size={disk['size']} partitions={disk['partitions']}")
        if MODE == "register":
            register_client(interface, mac, ip, inv)
        elif MODE in {"capture", "deploy"}:
            task = claim(MODE, mac, ip, inv)
            if not task:
                print(f"No queued {MODE} task. Returning to the maintenance shell.")
            elif MODE == "capture":
                capture(task, mac)
            else:
                deploy(task, mac, interface, ip)
        else:
            print(f"Unknown ZOS mode: {MODE}")
            return 1
        return 0
    except Exception as error:
        report_failure(str(error))
        return 1
    finally:
        print("A ZOS diagnostic shell is available. Type reboot to restart.", flush=True)


if __name__ == "__main__":
    result = main()
    try:
        os.execv("/bin/bash", ["bash", "-l"])
    except OSError:
        sys.exit(result)
