from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import csv
import os
import platform
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape

from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from server.pxe_services import PxeController
from zos_multicast import group_for_session, send_file as send_zos_multicast


VERSION = "0.22.6"
ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "manager_config.json"
DATA_DIR = ROOT / "data"
IMAGE_DIR = ROOT / "images"
TASK_FILE = DATA_DIR / "tasks.json"
NODE_FILE = DATA_DIR / "nodes.json"
REGISTRATION_FILE = DATA_DIR / "registrations.json"
IMAGE_CATALOG_FILE = DATA_DIR / "image_catalog.json"


def rebuild_image_catalog() -> list[dict]:
    """Build a lightweight metadata catalog without changing image payloads."""
    catalog = []
    IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    for image in sorted(IMAGE_DIR.glob("*.img.zst"), key=lambda p: p.stat().st_mtime, reverse=True):
        sidecar = read_json(image.with_suffix(image.suffix + ".json"), {})
        row = {
            "file": image.name,
            "name": str(sidecar.get("image_name") or image.name[:-8]),
            "architecture": normalize_architecture(str(sidecar.get("source_arch") or "unknown")),
            "image_type": str(sidecar.get("image_type") or "unknown"),
            "source_bytes": int(sidecar.get("source_bytes") or 0),
            "compressed_bytes": image.stat().st_size,
            "created_at": str(sidecar.get("created_at") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(image.stat().st_mtime))),
            "sha256": str(sidecar.get("sha256") or ""),
            "tags": list(sidecar.get("tags") or []),
            "note": str(sidecar.get("note") or ""),
        }
        catalog.append(row)
    atomic_json(IMAGE_CATALOG_FILE, catalog)
    return catalog


def normalize_architecture(value: str) -> str:
    value = str(value or "").strip().lower().replace("-", "_")
    if value in {"x86_64", "amd64", "i386", "i486", "i586", "i686"}:
        return "x86_64"
    if value in {"arm64", "aarch64"}:
        return "arm64"
    if value in {"loong64", "loongarch64", "loongarch_64"}:
        return "loongarch64"
    return "unknown"


def format_bytes_gib(value) -> str:
    try:
        size = int(value or 0)
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        return "未知"
    gib = size / (1024 ** 3)
    if gib >= 1024:
        return f"{gib / 1024:.1f} TiB"
    return f"{gib:.1f} GiB"


def client_hardware_info(registration: dict) -> dict:
    inventory = dict((registration or {}).get("inventory") or {})
    analysis = (registration or {}).get("disk_analysis") or analyze_disk_inventory(inventory)
    disks = list(analysis.get("disks") or [])
    largest = max((int(item.get("size") or 0) for item in disks), default=0)
    total = sum(int(item.get("size") or 0) for item in disks)
    return {
        "arch": normalize_architecture(str(inventory.get("arch") or "")),
        "cpu_model": str(inventory.get("cpu_model") or "").strip() or "未知",
        "cpu_cores": int(inventory.get("cpu_cores") or 0),
        "memory_bytes": int(inventory.get("memory_bytes") or 0),
        "disk_count": int(analysis.get("count") or len(disks)),
        "largest_disk_bytes": largest,
        "disk_total_bytes": total,
    }


def architecture_warning(image_arch: str, registration: dict) -> str:
    source_arch = normalize_architecture(str(image_arch or ""))
    target_arch = client_hardware_info(registration).get("arch", "unknown")
    if source_arch != "unknown" and target_arch != "unknown" and source_arch != target_arch:
        return f"CPU架构不匹配：镜像 {source_arch}，客户端 {target_arch}"
    return ""


def ipxe_architecture_setup() -> str:
    """Return iPXE labels that select only native maintenance assets."""
    return """set zos_arch unsupported
set zos_netargs
goto arch_${buildarch} || goto arch_unsupported

:arch_i386
set zos_arch x86_64
set zos_kernel bzImage
set zos_init init.xz
set zos_args loglevel=4 init=/sbin/init root=/dev/ram0 rw ramdisk_size=275000 keymap= boottype=usb consoleblank=0 rootfstype=ext4 hostname=zosclient.localdomain
goto arch_ready

:arch_x86_64
set zos_arch x86_64
set zos_kernel bzImage
set zos_init init.xz
set zos_args loglevel=4 init=/sbin/init root=/dev/ram0 rw ramdisk_size=275000 keymap= boottype=usb consoleblank=0 rootfstype=ext4 hostname=zosclient.localdomain
goto arch_ready

:arch_arm64
set zos_arch arm64
set zos_kernel Image
set zos_init init.cpio.gz
set zos_args loglevel=4 rdinit=/init init=/init rw consoleblank=0 hostname=zosclient.localdomain initrd=${zos_init} earlycon keep_bootcon console=ttyAMA0,115200n8 console=ttyS0,115200n8 console=tty0
set zos_netargs jy_client_ip=${net0/ip} jy_netmask=${net0/netmask} jy_gateway=${net0/gateway} jy_dns=${dns}
goto arch_ready

:arch_loong64
set zos_arch loongarch64
set zos_kernel vmlinuz
set zos_init initrd.xz
set zos_args loglevel=4 init=/init rw consoleblank=0 hostname=zosclient.localdomain
goto arch_ready

:arch_unsupported
echo Unsupported iPXE architecture: ${buildarch}
echo Supported: i386/x86_64, arm64, loong64
shell
exit

:arch_ready
echo ZOS architecture: ${zos_arch} (iPXE ${buildarch})
"""


def atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, path)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def natural_sort_key(value) -> tuple:
    """Return a stable natural-order key, so PC-2 sorts before PC-10."""
    parts = re.split(r"(\d+)", str(value or "").casefold())
    return tuple(
        (1, int(part)) if part.isdigit() else (0, part)
        for part in parts if part != ""
    )


def client_table_sort_key(column: int, value):
    """Return a type-safe sort key for a registered-client table column."""
    if column == 0:
        return 0 if str(value) == "在线" else 1
    if column == 1:
        return natural_sort_key(value)
    if column == 2:
        try:
            return int(ipaddress.IPv4Address(str(value).strip()))
        except ipaddress.AddressValueError:
            return -1
    if column in {7, 10}:
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1
    if column in {8, 9}:
        text = str(value or "").strip()
        match = re.match(r"^([0-9.]+)\s+(GiB|TiB)$", text)
        if match:
            amount = float(match.group(1))
            return amount * (1024 if match.group(2) == "TiB" else 1)
        return -1.0
    if column == 12:
        return str(value or "")
    return natural_sort_key(value)


def clients_in_batch_direction(clients: list[dict], direction: str) -> list[dict]:
    """Keep current visible list order, or reverse it for sequential assignment."""
    ordered = [dict(row) for row in clients]
    if str(direction or "forward").lower() == "reverse":
        ordered.reverse()
    return ordered


class SortableTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem with an explicit numeric/natural comparison key."""

    def __init__(self, value, sort_value=None):
        super().__init__(str(value))
        self.sort_value = sort_value if sort_value is not None else natural_sort_key(value)

    def __lt__(self, other):
        if isinstance(other, SortableTableWidgetItem):
            return self.sort_value < other.sort_value
        return super().__lt__(other)


def safe_name(value: str) -> str:
    value = re.sub(r"[^\w.-]+", "_", value.strip(), flags=re.UNICODE)
    return value.strip("._")[:80] or f"image-{int(time.time())}"


def normalize_mac(value: str) -> str:
    value = value.strip().lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        raise ValueError("MAC地址格式无效，应类似 00:11:22:33:44:55")
    return value


def normalize_post_action(value: str) -> str:
    value = value.strip().lower()
    if value not in {"none", "reboot", "shutdown"}:
        raise ValueError("任务完成动作无效")
    return value


def normalize_transfer_mode(value: str) -> str:
    value = value.strip().lower()
    if value not in {"unicast", "multicast"}:
        raise ValueError("下发传输模式无效")
    return value


def transfer_mode_text(value: str) -> str:
    return "组播同步" if value == "multicast" else "单独TCP"


def normalize_multicast_profile(value: str) -> str:
    value = value.strip().lower()
    if value not in {"compatible", "gigabit", "maximum"}:
        raise ValueError("组播速度模式无效")
    return value


def multicast_profile_text(value: str) -> str:
    return {
        "compatible": "兼容稳定",
        "gigabit": "千兆高速",
        "maximum": "高速网络/SSD",
    }.get(value, "千兆高速")


def format_duration(seconds) -> str:
    try:
        total = max(0, int(float(seconds)))
    except (TypeError, ValueError):
        return ""
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def safe_computer_name(value: str, mac: str) -> str:
    value = re.sub(r"[^A-Za-z0-9-]+", "-", value.strip()).strip("-")
    if not value or value.isdigit():
        value = f"ZOS-{mac.replace(':', '')[-6:]}"
    return value[:15].rstrip("-")


def normalize_group_name(value: str) -> str:
    value = re.sub(r"[\x00-\x1f\x7f]+", "", value).strip()
    return value[:40] or "默认组"


def normalize_group_list(value) -> list[str]:
    if isinstance(value, list):
        candidates = value
    else:
        candidates = re.split(r"[,，;；\r\n]+", str(value or ""))
    groups: list[str] = []
    for candidate in candidates:
        group = normalize_group_name(str(candidate))
        if group not in groups:
            groups.append(group)
    return groups or ["默认组"]


def fill_post_actions(combo: QComboBox) -> None:
    combo.addItem("任务成功后自动重启", "reboot")
    combo.addItem("任务成功后自动关机", "shutdown")
    combo.addItem("任务完成后停留在维护界面", "none")


def post_action_text(value: str) -> str:
    return {"reboot": "自动重启", "shutdown": "自动关机", "none": "停留"}.get(value, "停留")


def build_wol_packet(mac: str) -> bytes:
    normalized = normalize_mac(mac)
    raw = bytes.fromhex(normalized.replace(":", ""))
    return b"\xff" * 6 + raw * 16


def excel_column(index: int) -> str:
    value = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        value = chr(65 + remainder) + value
    return value


def write_xlsx(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    sheet_rows = []
    for row_index, values in enumerate([headers, *rows], start=1):
        cells = []
        for column_index, value in enumerate(values, start=1):
            reference = f"{excel_column(column_index)}{row_index}"
            style = ' s="1"' if row_index == 1 else ""
            cells.append(
                f'<c r="{reference}" t="inlineStr"{style}>'
                f'<is><t xml:space="preserve">{escape(str(value))}</t></is></c>'
            )
        sheet_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    column_widths = [10, 22, 16, 20, 16, 10, 18, 24, 22]
    columns = "".join(
        f'<col min="{index}" max="{index}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(column_widths, start=1)
    )
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<cols>{columns}</cols><sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        f'<sheetData>{"".join(sheet_rows)}</sheetData><autoFilter ref="A1:I1"/>'
        '</worksheet>'
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as book:
        book.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '</Types>',
        )
        book.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>',
        )
        book.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="客户端列表" sheetId="1" r:id="rId1"/></sheets></workbook>',
        )
        book.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
            '</Relationships>',
        )
        book.writestr(
            "xl/styles.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill></fills>'
            '<borders count="1"><border/></borders>'
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
            '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
            '</styleSheet>',
        )
        book.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def read_xlsx_rows(path: Path) -> list[list[str]]:
    """Read the first worksheet without requiring openpyxl."""
    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(path) as book:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in book.namelist():
            root = ElementTree.fromstring(book.read("xl/sharedStrings.xml"))
            for item in root.findall(f"{namespace}si"):
                shared.append("".join(node.text or "" for node in item.iter(f"{namespace}t")))
        sheets = sorted(
            name for name in book.namelist()
            if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)
        )
        if not sheets:
            raise ValueError("Excel文件中没有可读取的工作表")
        root = ElementTree.fromstring(book.read(sheets[0]))
    output: list[list[str]] = []
    for row in root.iter(f"{namespace}row"):
        values: dict[int, str] = {}
        for cell in row.findall(f"{namespace}c"):
            reference = str(cell.get("r") or "")
            match = re.match(r"([A-Z]+)", reference)
            if not match:
                continue
            column = 0
            for character in match.group(1):
                column = column * 26 + ord(character) - 64
            cell_type = str(cell.get("t") or "")
            if cell_type == "inlineStr":
                value = "".join(
                    node.text or "" for node in cell.iter(f"{namespace}t")
                )
            else:
                node = cell.find(f"{namespace}v")
                value = node.text if node is not None and node.text is not None else ""
                if cell_type == "s" and value.isdigit():
                    index = int(value)
                    value = shared[index] if index < len(shared) else ""
            values[column - 1] = str(value).strip()
        if values:
            output.append([values.get(index, "") for index in range(max(values) + 1)])
        if len(output) > 50000:
            raise ValueError("客户端列表超过50000行，请拆分后导入")
    return output


def read_text_rows(path: Path) -> list[list[str]]:
    raw = path.read_bytes()
    text = ""
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if not text:
        raise ValueError("文本文件不是UTF-8或GB18030编码")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters="\t,;，；")
        return [[cell.strip() for cell in row] for row in csv.reader(text.splitlines(), dialect)]
    except csv.Error:
        return [
            [cell.strip() for cell in re.split(r"\t|,|，", line)]
            for line in text.splitlines() if line.strip()
        ]


def parse_client_import(path: Path) -> tuple[list[dict], list[str]]:
    if path.suffix.lower() == ".xlsx":
        rows = read_xlsx_rows(path)
    elif path.suffix.lower() in {".txt", ".csv"}:
        rows = read_text_rows(path)
    else:
        raise ValueError("仅支持.xlsx、.txt或.csv客户端列表")
    aliases = {
        "mac": {"mac", "mac地址", "物理地址", "网卡地址"},
        "name": {"客户端名称", "计算机名", "电脑名称", "名称", "name", "hostname"},
        "ip": {"ip", "ip地址", "注册ip", "注册ip地址", "ipv4", "ipv4地址", "address"},
        "group": {"组", "分组", "客户端分组", "group"},
    }

    def clean_header(value: str) -> str:
        return re.sub(r"[\s_\-]+", "", str(value).strip().lower())

    columns: dict[str, int] = {}
    header_index = -1
    for index, row in enumerate(rows[:20]):
        normalized = [clean_header(value) for value in row]
        candidate: dict[str, int] = {}
        for field, names in aliases.items():
            normalized_names = {clean_header(name) for name in names}
            match = next((i for i, value in enumerate(normalized) if value in normalized_names), None)
            if match is not None:
                candidate[field] = match
        if "mac" in candidate:
            columns = candidate
            header_index = index
            break
    if header_index < 0:
        raise ValueError("没有找到MAC列；表头可使用：MAC、客户端名称、IP、组")

    imported: dict[str, dict] = {}
    errors: list[str] = []
    for line_number, row in enumerate(rows[header_index + 1:], start=header_index + 2):
        if not any(str(value).strip() for value in row):
            continue

        def value(field: str) -> str:
            column = columns.get(field, -1)
            return str(row[column]).strip() if 0 <= column < len(row) else ""

        try:
            mac = normalize_mac(value("mac"))
            ip = value("ip")
            if ip:
                ip = str(ipaddress.IPv4Address(ip))
            name = value("name") or f"ZOS-{mac.replace(':', '')[-6:]}"
            imported[mac] = {
                "mac": mac,
                "name": name[:80],
                "ip": ip,
                "group": normalize_group_name(value("group") or "默认组"),
            }
        except ValueError as exc:
            errors.append(f"第{line_number}行：{exc}")
    if not imported:
        detail = f"\n{errors[0]}" if errors else ""
        raise ValueError(f"没有找到可导入的有效客户端{detail}")
    return list(imported.values()), errors


def analyze_disk_inventory(inventory: dict) -> dict:
    disks = []
    for item in inventory.get("blockdevices", []) if isinstance(inventory, dict) else []:
        name = str(item.get("name", ""))
        path = str(item.get("path") or (f"/dev/{name}" if name else ""))
        try:
            size = int(item.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if item.get("type") != "disk" or size <= 0 or re.match(r"^(nbd|loop|ram|sr|fd|zram|rbd)", name):
            continue
        children = item.get("children") if isinstance(item.get("children"), list) else []
        filesystems = {
            str(child.get("fstype") or "").lower()
            for child in children if isinstance(child, dict) and child.get("fstype")
        }
        score = len(children) * 2
        if "ntfs" in filesystems:
            score += 50
        if filesystems & {"ext2", "ext3", "ext4", "xfs", "btrfs"}:
            score += 45
        if filesystems & {"vfat", "fat", "fat32"}:
            score += 20
        if "swap" in filesystems:
            score += 5
        if len(children) > 1:
            score += 10
        if "ntfs" in filesystems and filesystems & {"vfat", "fat", "fat32"}:
            system_hint = "疑似Windows系统盘"
        elif filesystems & {"ext2", "ext3", "ext4", "xfs", "btrfs"}:
            system_hint = "疑似Linux系统盘"
        elif filesystems:
            system_hint = "数据盘或未知系统"
        else:
            system_hint = "未识别到文件系统"
        disks.append({
            "path": path, "size": size, "partitions": len(children),
            "filesystems": sorted(filesystems), "score": score, "system_hint": system_hint,
        })
    disks.sort(key=lambda row: (row["score"], row["size"]), reverse=True)
    return {
        "count": len(disks),
        "selected": disks[0]["path"] if disks else "",
        "system_hint": disks[0]["system_hint"] if disks else "未检测到有效硬盘",
        "disks": disks,
    }


def default_config() -> dict:
    return {
        "tftp_root": str(ROOT / "tftp"),
        "pxe_interface_name": "",
        "pxe_server_ip": "192.168.5.1",
        "dhcp_mode": "server",
        "uefi_ipxe_driver": "snp",
        "dhcp_subnet_mask": "255.255.255.0",
        "dhcp_pool_start": "192.168.5.100",
        "dhcp_pool_end": "192.168.5.200",
        "dhcp_gateway": "192.168.5.254",
        "dhcp_dns": "223.6.6.6,114.114.114.114",
        "dhcp_lease_seconds": 28800,
        "dhcp_port": 67,
        "proxy_dhcp_port": 67,
        "pxe_binl_port": 4011,
        "tftp_port": 69,
        "tcp_port": 8090,
        "multicast_start_timeout": 900,
        "zosmc_handshake_timeout": 60,
        "local_boot_timeout": 10,
        "client_groups": ["默认组"],
        "agent_token": secrets.token_urlsafe(24),
    }


class JsonTaskStore:
    def __init__(self):
        self.lock = threading.RLock()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        IMAGE_DIR.mkdir(parents=True, exist_ok=True)

    def tasks(self) -> list[dict]:
        with self.lock:
            return read_json(TASK_FILE, [])

    def _save_tasks(self, rows: list[dict]) -> None:
        atomic_json(TASK_FILE, rows)

    def registrations(self) -> list[dict]:
        with self.lock:
            return read_json(REGISTRATION_FILE, [])

    def _sync_pending_task_identity(self, updates_by_mac: dict[str, dict]) -> None:
        """Keep queued MAC-targeted tasks aligned with the registered identity."""
        if not updates_by_mac:
            return
        tasks = self.tasks()
        changed = False
        for task in tasks:
            mac = str(task.get("target_mac") or "").lower()
            identity = updates_by_mac.get(mac)
            if not identity or task.get("status") not in {"queued", "failed"}:
                continue
            name = str(identity.get("name") or "未命名客户端")[:80]
            ip = str(identity.get("ip") or "")[:45]
            task["registered_name"] = name
            task["registered_ip"] = ip
            task["hostname"] = name
            task["client_ip"] = ip
            if task.get("action") == "deploy":
                if bool(task.get("apply_computer_name")):
                    task["identity_name"] = safe_computer_name(name, mac)
                if bool(task.get("apply_static_ip")):
                    task["identity_ip"] = ip
            changed = True
        if changed:
            self._save_tasks(tasks)

    def register_client(self, request: dict) -> dict:
        mac = normalize_mac(str(request.get("mac", "")))
        hostname = str(request.get("hostname") or "zosclient")[:80]
        requested_name = str(request.get("name") or hostname).strip()[:80] or hostname
        requested_group = normalize_group_name(str(request.get("group") or "默认组"))
        reported_ip = str(request.get("ip") or "")[:45]
        inventory = request.get("inventory", {})
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            rows = self.registrations()
            existing = next((item for item in rows if item.get("mac") == mac), {})
            if existing:
                # Once a MAC is registered, the management record is authoritative.
                # PXE boots only refresh live status; administrators edit identity in the UI.
                configured_name = str(existing.get("name") or requested_name)[:80]
                configured_group = normalize_group_name(
                    str(existing.get("group") or requested_group)
                )
                configured_ip = str(existing.get("ip") or "")[:45]
            else:
                configured_name = requested_name
                configured_group = requested_group
                configured_ip = reported_ip
            row = dict(existing)
            row.update({
                "mac": mac,
                "name": configured_name,
                "hostname": hostname,
                "group": configured_group,
                "ip": configured_ip,
                "reported_ip": reported_ip,
                "inventory": inventory,
                "disk_analysis": analyze_disk_inventory(inventory),
                "registered_at": existing.get("registered_at") or now,
                "last_seen": now,
            })
            rows = [item for item in rows if item.get("mac") != mac]
            rows.append(row)
            atomic_json(REGISTRATION_FILE, rows)

            node = dict(row)
            node.update({
                "hostname": hostname,
                "ip": reported_ip,
                "configured_name": configured_name,
                "configured_ip": configured_ip,
                "last_seen": now,
            })
            nodes = [item for item in read_json(NODE_FILE, []) if item.get("mac") != mac]
            nodes.append(node)
            atomic_json(NODE_FILE, nodes)
            self._sync_pending_task_identity({mac: row})
        return row

    def save_registration(self, mac: str, name: str, group: str = "默认组") -> dict:
        mac = normalize_mac(mac)
        group = normalize_group_name(group)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            rows = self.registrations()
            existing = next((item for item in rows if item.get("mac") == mac), {})
            row = dict(existing)
            row.update({
                "mac": mac,
                "name": (name.strip() or existing.get("hostname") or "未命名客户端")[:80],
                "group": group,
                "ip": str(existing.get("ip") or "")[:45],
                "identity_locked": True,
                "identity_updated_at": now,
                "registered_at": existing.get("registered_at") or now,
                "last_seen": existing.get("last_seen", ""),
            })
            rows = [item for item in rows if item.get("mac") != mac]
            rows.append(row)
            atomic_json(REGISTRATION_FILE, rows)
            nodes = read_json(NODE_FILE, [])
            for node in nodes:
                if str(node.get("mac") or "").lower() == mac:
                    node["name"] = row["name"]
                    node["group"] = row["group"]
                    node["configured_name"] = row["name"]
                    node["configured_ip"] = row["ip"]
            atomic_json(NODE_FILE, nodes)
            self._sync_pending_task_identity({mac: row})
            return row

    def update_registration_identities(self, updates: list[dict]) -> int:
        """Update one or many registered client names/IPs and queued task snapshots."""
        if not updates:
            return 0
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            rows = self.registrations()
            by_mac = {
                str(item.get("mac") or "").lower(): dict(item)
                for item in rows if item.get("mac")
            }
            normalized: dict[str, dict] = {}
            for source in updates:
                mac = normalize_mac(str(source.get("mac") or ""))
                if mac not in by_mac:
                    raise ValueError(f"客户端未注册：{mac}")
                existing = by_mac[mac]
                name = str(source.get("name", existing.get("name") or "")).strip()[:80]
                if not name:
                    raise ValueError(f"客户端 {mac} 的计算机名不能为空")
                raw_ip = str(source.get("ip", existing.get("ip") or "")).strip()
                address = str(ipaddress.IPv4Address(raw_ip)) if raw_ip else ""
                normalized[mac] = {"mac": mac, "name": name, "ip": address}

            task_rows = self.tasks()
            active_by_mac = {
                str(task.get("target_mac") or task.get("mac") or "").lower()
                for task in task_rows
                if task.get("status") in {"assigned", "ready", "uploading", "deploying"}
            }
            active_selected = [mac for mac in normalized if mac in active_by_mac]
            if active_selected:
                names = "、".join(normalized[mac]["name"] for mac in active_selected[:5])
                raise ValueError(
                    f"客户端正在执行或已经领取任务，暂不能修改身份信息：{names}"
                )
            pending_static = {
                str(task.get("target_mac") or "").lower()
                for task in task_rows
                if task.get("status") in {"queued", "failed"}
                and task.get("action") == "deploy"
                and bool(task.get("apply_static_ip"))
            }
            for mac, update in normalized.items():
                if mac in pending_static and not update["ip"]:
                    raise ValueError(
                        f"客户端 {update['name']} 有待执行的固定IP下发任务，"
                        "请先填写IP或取消该任务后再清空IP"
                    )

            changed_ip_macs = {
                mac for mac, update in normalized.items()
                if update["ip"] != str(by_mac[mac].get("ip") or "")
            }
            final_ip_owners: dict[str, list[str]] = {}
            for mac, row in by_mac.items():
                value = normalized.get(mac, {}).get("ip", str(row.get("ip") or ""))
                if value:
                    final_ip_owners.setdefault(value, []).append(mac)
            for value, owners in final_ip_owners.items():
                if len(owners) > 1 and any(mac in changed_ip_macs for mac in owners):
                    raise ValueError(
                        f"IP地址重复：{value} 同时分配给 {'、'.join(owners[:4])}"
                    )

            for mac, update in normalized.items():
                row = by_mac[mac]
                row.update({
                    "name": update["name"],
                    "ip": update["ip"],
                    "identity_locked": True,
                    "identity_updated_at": now,
                })
                by_mac[mac] = row
            ordered = [by_mac[str(row.get("mac") or "").lower()] for row in rows]
            atomic_json(REGISTRATION_FILE, ordered)

            nodes = read_json(NODE_FILE, [])
            for node in nodes:
                mac = str(node.get("mac") or "").lower()
                if mac in normalized:
                    node["name"] = normalized[mac]["name"]
                    node["configured_name"] = normalized[mac]["name"]
                    node["configured_ip"] = normalized[mac]["ip"]
            atomic_json(NODE_FILE, nodes)
            self._sync_pending_task_identity({mac: by_mac[mac] for mac in normalized})
            return len(normalized)

    def import_registrations(self, imported: list[dict]) -> tuple[int, int]:
        created = 0
        updated = 0
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            rows = self.registrations()
            by_mac = {str(item.get("mac") or "").lower(): dict(item) for item in rows}
            nodes = read_json(NODE_FILE, [])
            node_by_mac = {
                str(item.get("mac") or "").lower(): dict(item)
                for item in nodes if item.get("mac")
            }
            changed: dict[str, dict] = {}
            for source in imported:
                mac = normalize_mac(str(source.get("mac") or ""))
                existing = by_mac.get(mac, {})
                created += int(not existing)
                updated += int(bool(existing))
                row = dict(existing)
                row.update({
                    "mac": mac,
                    "name": str(source.get("name") or existing.get("name") or f"ZOS-{mac[-8:].replace(':', '')}")[:80],
                    "ip": str(source.get("ip") or "")[:45],
                    "group": normalize_group_name(str(source.get("group") or "默认组")),
                    "identity_locked": True,
                    "identity_updated_at": now,
                    "registered_at": existing.get("registered_at") or now,
                    "last_seen": existing.get("last_seen", ""),
                    "imported_at": now,
                })
                by_mac[mac] = row
                changed[mac] = row
                if mac in node_by_mac:
                    node_by_mac[mac].update({
                        "name": row["name"], "group": row["group"],
                        "configured_name": row["name"], "configured_ip": row["ip"],
                    })
            atomic_json(REGISTRATION_FILE, list(by_mac.values()))
            if nodes:
                atomic_json(NODE_FILE, list(node_by_mac.values()))
            self._sync_pending_task_identity(changed)
        return created, updated

    def delete_registrations(self, macs: list[str]) -> int:
        normalized = {normalize_mac(mac) for mac in macs}
        if not normalized:
            return 0
        with self.lock:
            tasks = self.tasks()
            sessions = {
                str(row.get("multicast_session_id") or "")
                for row in tasks
                if row.get("target_mac") in normalized and row.get("multicast_session_id")
            }
            active = [
                row for row in tasks
                if (
                    row.get("target_mac") in normalized
                    or str(row.get("multicast_session_id") or "") in sessions
                )
                and row.get("status") in {"assigned", "ready", "uploading", "deploying"}
            ]
            if active:
                names = "、".join(str(row.get("id") or "") for row in active[:5])
                raise ValueError(f"客户端仍有正在执行的任务：{names}；请先等待完成或取消任务")
            for row in tasks:
                same_target = (
                    row.get("target_mac") in normalized
                    or str(row.get("multicast_session_id") or "") in sessions
                )
                if same_target and row.get("status") in {"queued", "failed"}:
                    row["status"] = "cancelled"
                    if row.get("multicast_session_id"):
                        row["multicast_state"] = "cancelled"
                    row["message"] = "客户端记录已删除，待执行任务自动取消"
            self._save_tasks(tasks)
            registrations = self.registrations()
            remaining = [row for row in registrations if row.get("mac") not in normalized]
            atomic_json(REGISTRATION_FILE, remaining)
            nodes = [
                row for row in read_json(NODE_FILE, [])
                if str(row.get("mac") or "").lower() not in normalized
            ]
            atomic_json(NODE_FILE, nodes)
            return len(registrations) - len(remaining)

    def delete_tasks(self, task_ids: list[str], force: bool = False) -> tuple[int, list[str]]:
        selected = {str(task_id) for task_id in task_ids if task_id}
        if not selected:
            return 0, []
        with self.lock:
            rows = self.tasks()
            sessions = {
                str(row.get("multicast_session_id") or "")
                for row in rows if row.get("id") in selected and row.get("multicast_session_id")
            }
            if sessions:
                selected.update(
                    str(row.get("id") or "") for row in rows
                    if str(row.get("multicast_session_id") or "") in sessions
                )
            active = [
                row for row in rows
                if row.get("id") in selected
                and row.get("status") in {"assigned", "ready", "uploading", "deploying"}
            ]
            if active and not force:
                names = "、".join(str(row.get("id") or "") for row in active[:5])
                raise ValueError(f"任务正在执行或已被客户端领取，不能删除：{names}")
            # force=True is intentionally allowed for powered-off/crashed clients.
            # Multicast sessions are returned to the caller so their sender thread/process
            # can be stopped immediately after the task records are removed.
            remaining = [row for row in rows if row.get("id") not in selected]
            self._save_tasks(remaining)
            return len(rows) - len(remaining), sorted(sessions)

    def cancel_pending_for_mac(self, mac: str) -> None:
        mac = normalize_mac(mac)
        with self.lock:
            rows = self.tasks()
            for row in rows:
                if row.get("target_mac") == mac and row.get("status") in {"queued", "failed"}:
                    row["status"] = "cancelled"
                    row["message"] = "已被新的客户端启动策略替换"
            self._save_tasks(rows)

    def create_task(
        self, image_name: str, device: str, image_type: str, filesystem: str,
        target_mac: str = "", post_action: str = "none", target_group: str = "",
    ) -> dict:
        target_mac = normalize_mac(target_mac) if target_mac else ""
        post_action = normalize_post_action(post_action)
        registration = next(
            (item for item in self.registrations() if item.get("mac") == target_mac),
            {},
        ) if target_mac else {}
        registered_name = str(registration.get("name") or "")[:80]
        registered_ip = str(registration.get("ip") or "")[:45]
        row = {
            "id": uuid.uuid4().hex[:12],
            "action": "capture",
            "image_name": safe_name(image_name),
            "device": device,
            "image_type": image_type,
            "filesystem": filesystem,
            "status": "queued",
            "mac": "",
            "hostname": registered_name,
            "client_ip": registered_ip,
            "registered_name": registered_name,
            "registered_ip": registered_ip,
            "target_mac": target_mac,
            "target_group": normalize_group_name(target_group) if target_group else "",
            "post_action": post_action,
            "received_bytes": 0,
            "message": (
                f"等待指定客户端 {target_mac} 开机自动上传"
                if target_mac else "等待客户端从PXE选择上传镜像"
            ),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self.lock:
            rows = self.tasks()
            rows.append(row)
            self._save_tasks(rows)
        return row

    def create_deploy_task(
        self, image_file: str, device: str = "auto", target_mac: str = "",
        post_action: str = "none", target_group: str = "",
        transfer_mode: str = "unicast", multicast_session_id: str = "",
        multicast_expected: int = 0, multicast_profile: str = "gigabit",
        identity: dict | None = None,
    ) -> dict:
        target_mac = normalize_mac(target_mac) if target_mac else ""
        post_action = normalize_post_action(post_action)
        transfer_mode = normalize_transfer_mode(transfer_mode)
        if transfer_mode == "multicast":
            if not multicast_session_id or multicast_expected < 2:
                raise ValueError("组播任务必须包含会话编号和至少2台客户端")
            multicast_profile = normalize_multicast_profile(multicast_profile)
        else:
            multicast_session_id = ""
            multicast_expected = 0
            multicast_profile = ""
        identity = dict(identity or {})
        legacy_enabled = bool(identity.get("enabled"))
        apply_computer_name = bool(identity.get("apply_name", legacy_enabled))
        apply_static_ip = bool(identity.get("apply_ip", legacy_enabled))
        identity_network_mode = str(identity.get("network_mode") or "").lower()
        if identity_network_mode not in {"static", "dhcp", "unchanged"}:
            identity_network_mode = "static" if apply_static_ip else "unchanged"
        if apply_static_ip:
            identity_network_mode = "static"
        apply_identity = (
            apply_computer_name or identity_network_mode in {"static", "dhcp"}
        )
        identity_name = ""
        identity_ip = ""
        identity_prefix = 24
        identity_gateway = ""
        identity_dns: list[str] = []
        if apply_computer_name:
            identity_name = safe_computer_name(
                str(identity.get("name") or ""), target_mac
            )
        if apply_static_ip:
            identity_ip = str(ipaddress.IPv4Address(str(identity.get("ip") or "")))
            identity_prefix = int(identity.get("prefix") or 24)
            if not 1 <= identity_prefix <= 32:
                raise ValueError("客户端静态IP前缀长度无效")
            if identity.get("gateway"):
                identity_gateway = str(ipaddress.IPv4Address(str(identity["gateway"])))
            for value in identity.get("dns") or []:
                address = str(ipaddress.IPv4Address(str(value)))
                if address not in identity_dns:
                    identity_dns.append(address)
        image_path = (IMAGE_DIR / Path(image_file).name).resolve()
        try:
            image_path.relative_to(IMAGE_DIR.resolve())
        except ValueError as exc:
            raise ValueError("镜像路径不在 images 目录中") from exc
        if image_path.suffixes[-2:] != [".img", ".zst"] or not image_path.is_file():
            raise ValueError("请选择 images 目录中的 .img.zst 整盘镜像")
        metadata = read_json(image_path.with_suffix(image_path.suffix + ".json"), {})
        image_type = str(metadata.get("image_type") or "")
        if image_type != "raw_disk":
            raise ValueError("当前仅支持下发 RAW 整盘镜像；该镜像不是 RAW 整盘格式")
        source_bytes = int(metadata.get("source_bytes") or 0)
        if source_bytes <= 0:
            raise ValueError("镜像缺少源硬盘容量信息，不能安全下发")
        source_arch = normalize_architecture(str(metadata.get("source_arch") or ""))
        registration = next(
            (item for item in self.registrations() if item.get("mac") == target_mac),
            {},
        ) if target_mac else {}
        registered_name = str(registration.get("name") or "")[:80]
        registered_ip = str(registration.get("ip") or "")[:45]
        compatibility_warning = architecture_warning(source_arch, registration) if target_mac else ""
        row = {
            "id": uuid.uuid4().hex[:12],
            "action": "deploy",
            "image_name": image_path.name[:-8],
            "image_path": str(image_path),
            "image_type": "raw_disk",
            "filesystem": str(metadata.get("filesystem") or "auto"),
            "device": device,
            "source_bytes": source_bytes,
            "compressed_bytes": image_path.stat().st_size,
            "checksum": str(metadata.get("checksum") or ""),
            "source_arch": source_arch,
            "compatibility_warning": compatibility_warning,
            "status": "queued",
            "mac": "",
            "hostname": registered_name,
            "client_ip": registered_ip,
            "registered_name": registered_name,
            "registered_ip": registered_ip,
            "target_mac": target_mac,
            "target_group": normalize_group_name(target_group) if target_group else "",
            "post_action": post_action,
            "transfer_mode": transfer_mode,
            "multicast_session_id": multicast_session_id,
            "multicast_expected": multicast_expected,
            "multicast_profile": multicast_profile,
            "multicast_ready": False,
            "multicast_state": "waiting" if transfer_mode == "multicast" else "",
            "received_bytes": 0,
            "written_bytes": 0,
            "progress_percent": 0.0,
            "started_at": "",
            "started_ts": 0.0,
            "elapsed_seconds": 0,
            "apply_registered_identity": apply_identity,
            "apply_computer_name": apply_computer_name,
            "apply_static_ip": apply_static_ip,
            "identity_network_mode": identity_network_mode,
            "identity_name": identity_name,
            "identity_ip": identity_ip,
            "identity_prefix": identity_prefix,
            "identity_gateway": identity_gateway,
            "identity_dns": identity_dns,
            "identity_status": "pending" if apply_identity else "disabled",
            "message": (
                ((compatibility_warning + "；") if compatibility_warning else "")
                + (
                    (
                        f"组播会话等待 {multicast_expected} 台客户端全部上线"
                        if transfer_mode == "multicast"
                        else f"等待指定客户端 {target_mac} 开机自动下发"
                    )
                    if target_mac else "等待新客户端从PXE选择下发镜像"
                )
            ),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self.lock:
            rows = self.tasks()
            rows.append(row)
            self._save_tasks(rows)
        return row

    def cancel(self, task_id: str) -> None:
        with self.lock:
            rows = self.tasks()
            selected = next((row for row in rows if row.get("id") == task_id), None)
            session_id = str((selected or {}).get("multicast_session_id") or "")
            for row in rows:
                same_target = row.get("id") == task_id or (
                    session_id and row.get("multicast_session_id") == session_id
                )
                if same_target and row["status"] in {"queued", "assigned", "ready", "failed"}:
                    row["status"] = "cancelled"
                    row["multicast_state"] = "cancelled"
                    row["message"] = "组播会话已取消" if session_id else "已取消"
            self._save_tasks(rows)

    def claim(self, request: dict) -> dict | None:
        mac = normalize_mac(str(request.get("mac", "")))
        mode = str(request.get("mode") or "capture").lower()
        automatic = bool(request.get("automatic", False))
        if mode not in {"capture", "deploy"}:
            raise ValueError("任务模式无效")
        inventory = request.get("inventory", {})
        client_arch = normalize_architecture(str(inventory.get("arch") or ""))
        disk_analysis = analyze_disk_inventory(inventory)
        node = {
            "mac": mac,
            "hostname": str(request.get("hostname", "zosclient"))[:80],
            "ip": str(request.get("ip", ""))[:45],
            "inventory": inventory,
            "disk_analysis": disk_analysis,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with self.lock:
            registration = next(
                (item for item in self.registrations() if item.get("mac") == mac),
                {},
            )
            display_name = str(
                registration.get("name") or request.get("hostname") or "zosclient"
            )[:80]
            nodes = read_json(NODE_FILE, [])
            nodes = [item for item in nodes if item.get("mac") != mac]
            nodes.append(node)
            atomic_json(NODE_FILE, nodes)
            rows = self.tasks()
            eligible = [
                row for row in rows
                if row.get("status") == "queued"
                and str(row.get("action") or "capture") == mode
                and str(row.get("target_mac") or "") in {"", mac}
            ]
            task = next((row for row in eligible if row.get("target_mac") == mac), None)
            if not task and not automatic:
                task = next((row for row in eligible if not row.get("target_mac")), None)
            if not task:
                self._save_tasks(rows)
                return None
            image_arch = normalize_architecture(str(task.get("source_arch") or ""))
            claim_warning = ""
            if mode == "deploy" and image_arch != "unknown" and client_arch != "unknown" and client_arch != image_arch:
                claim_warning = f"CPU架构不匹配：镜像 {image_arch}，客户端 {client_arch}；管理员已确认继续下发"
                task["compatibility_warning"] = claim_warning
            task["status"] = "assigned"
            task["mac"] = mac
            task["hostname"] = display_name
            task["registered_name"] = display_name
            task["registered_ip"] = str(registration.get("ip") or "")[:45]
            task["reported_ip"] = str(node["ip"] or "")[:45]
            task["client_ip"] = str(registration.get("ip") or node["ip"])[:45]
            task["client_arch"] = client_arch
            task["message"] = (
                (claim_warning + "；" if claim_warning else "")
                + f"检测到{disk_analysis['count']}块有效硬盘；"
                f"候选系统盘 {disk_analysis['selected'] or '无'}；"
                f"{disk_analysis['system_hint']}；客户端已领取{('上传' if mode == 'capture' else '下发')}任务"
            )
            self._save_tasks(rows)
            return dict(task)

    def multicast_ready(self, task_id: str, mac: str) -> dict:
        mac = normalize_mac(mac)
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task:
                raise ValueError("任务不存在")
            if (
                task.get("action") != "deploy"
                or task.get("transfer_mode") != "multicast"
                or task.get("mac") != mac
            ):
                raise ValueError("该任务不是此客户端的组播下发任务")
            if task.get("status") not in {"assigned", "ready", "deploying"}:
                raise ValueError(f"组播任务状态不可就绪：{task.get('status')}")
            session_id = str(task.get("multicast_session_id") or "")
            session_rows = [
                row for row in rows
                if row.get("multicast_session_id") == session_id
                and row.get("status") != "cancelled"
            ]
            expected = int(task.get("multicast_expected") or len(session_rows))
            task["multicast_ready"] = True
            if task.get("status") == "assigned":
                task["status"] = "ready"
            ready_count = sum(bool(row.get("multicast_ready")) for row in session_rows)
            should_start = (
                ready_count == expected
                and expected == len(session_rows)
                and all(row.get("status") in {"ready", "deploying", "completed"} for row in session_rows)
                and not any(row.get("multicast_state") in {"starting", "running", "sent"} for row in session_rows)
            )
            if should_start:
                for row in session_rows:
                    row["multicast_state"] = "starting"
                    row["message"] = f"全部 {expected} 台已就绪，正在启动可靠组播"
            else:
                for row in session_rows:
                    if row.get("multicast_state") not in {"starting", "running", "sent"}:
                        row["message"] = f"等待组内客户端上线：{ready_count}/{expected} 台已就绪"
            self._save_tasks(rows)
            return {
                "task": dict(task),
                "session_id": session_id,
                "expected": expected,
                "ready_count": ready_count,
                "state": str(task.get("multicast_state") or "waiting"),
                "should_start": should_start,
            }

    def multicast_session(self, session_id: str) -> dict:
        with self.lock:
            rows = [
                row for row in self.tasks()
                if row.get("multicast_session_id") == session_id
                and row.get("status") != "cancelled"
            ]
            if not rows:
                raise ValueError("组播会话不存在或已取消")
            expected = int(rows[0].get("multicast_expected") or len(rows))
            return {
                "session_id": session_id,
                "state": str(rows[0].get("multicast_state") or "waiting"),
                "expected": expected,
                "ready_count": sum(bool(row.get("multicast_ready")) for row in rows),
                "image_path": str(rows[0].get("image_path") or ""),
                "rows": [dict(row) for row in rows],
            }

    def set_multicast_state(self, session_id: str, state: str, message: str) -> None:
        with self.lock:
            rows = self.tasks()
            for row in rows:
                if (
                    row.get("multicast_session_id") == session_id
                    and row.get("status") not in {"cancelled", "completed"}
                ):
                    row["multicast_state"] = state
                    if state == "running":
                        row["status"] = "deploying"
                    elif state == "failed":
                        row["status"] = "failed"
                    row["message"] = message[:300]
            self._save_tasks(rows)

    def begin_upload(
        self, task_id: str, mac: str, source_bytes: int,
        device: str, image_type: str, filesystem: str, source_arch: str = "unknown",
    ) -> tuple[dict, Path]:
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row["id"] == task_id), None)
            if not task:
                raise ValueError("任务不存在")
            if str(task.get("action") or "capture") != "capture":
                raise ValueError("该任务不是上传镜像任务")
            if task.get("mac") != mac.lower() or task["status"] not in {"assigned", "uploading"}:
                raise ValueError("任务与客户端不匹配")
            if image_type not in {"raw_disk", "partclone_partition"}:
                raise ValueError("客户端报告的镜像类型无效")
            task["status"] = "uploading"
            task["source_bytes"] = max(0, int(source_bytes))
            task["device"] = device
            task["image_type"] = image_type
            task["filesystem"] = filesystem or "auto"
            task["source_arch"] = normalize_architecture(source_arch)
            task["received_bytes"] = 0
            task["message"] = "正在接收压缩镜像"
            self._save_tasks(rows)
            return dict(task), IMAGE_DIR / f"{safe_name(task['image_name'])}.img.zst.part"

    def progress(self, task_id: str, received: int) -> None:
        with self.lock:
            rows = self.tasks()
            for row in rows:
                if row["id"] == task_id:
                    if row.get("action") == "deploy":
                        row["network_received_bytes"] = received
                        if not int(row.get("written_bytes") or 0):
                            row["message"] = f"正在接收镜像：{received / 1024 / 1024:.1f} MiB"
                    else:
                        row["received_bytes"] = received
                        row["message"] = f"正在上传：{received / 1024 / 1024:.1f} MiB"
                    break
            self._save_tasks(rows)

    def deploy_started(self, task_id: str, mac: str) -> None:
        mac = normalize_mac(mac)
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task or task.get("action") != "deploy" or task.get("mac") != mac:
                raise ValueError("下发任务与客户端不匹配")
            if task.get("status") not in {"assigned", "ready", "deploying"}:
                raise ValueError("下发任务当前不能开始")
            now = time.time()
            task["status"] = "deploying"
            task["started_ts"] = float(task.get("started_ts") or now)
            task["started_at"] = task.get("started_at") or time.strftime("%Y-%m-%d %H:%M:%S")
            task["message"] = "客户端已开始接收并写入镜像"
            self._save_tasks(rows)

    def deploy_progress(self, task_id: str, mac: str, written_bytes: int) -> None:
        mac = normalize_mac(mac)
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task or task.get("action") != "deploy" or task.get("mac") != mac:
                raise ValueError("进度任务与客户端不匹配")
            if task.get("status") not in {"deploying", "completed", "completed_warning"}:
                raise ValueError("下发任务不在写盘状态")
            total = max(1, int(task.get("source_bytes") or 1))
            written = max(0, min(int(written_bytes), total))
            started_ts = float(task.get("started_ts") or time.time())
            task["written_bytes"] = written
            task["received_bytes"] = written
            task["progress_percent"] = round(written * 100.0 / total, 1)
            task["elapsed_seconds"] = max(0, int(time.time() - started_ts))
            task["last_progress_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            task["message"] = (
                f"客户端写盘 {task['progress_percent']:.1f}%："
                f"{written / 1024 / 1024 / 1024:.2f}/"
                f"{total / 1024 / 1024 / 1024:.2f} GiB，"
                f"耗时 {format_duration(task['elapsed_seconds'])}"
            )
            self._save_tasks(rows)

    def complete(self, task_id: str, partial: Path, received: int, checksum: str) -> Path:
        with self.lock:
            rows = self.tasks()
            task = next(row for row in rows if row["id"] == task_id)
            target = IMAGE_DIR / f"{safe_name(task['image_name'])}.img.zst"
            os.replace(partial, target)
            task.update({
                "status": "completed",
                "received_bytes": received,
                "checksum": checksum,
                "image_path": str(target),
                "message": "镜像上传完成",
                "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            self._save_tasks(rows)
            atomic_json(target.with_suffix(target.suffix + ".json"), task)
            return target

    def begin_download(self, task_id: str, mac: str) -> tuple[dict, Path]:
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task:
                raise ValueError("任务不存在")
            if task.get("action") != "deploy":
                raise ValueError("该任务不是镜像下发任务")
            if task.get("transfer_mode") == "multicast":
                raise ValueError("组播任务不能使用单独TCP下载")
            if task.get("mac") != mac.lower() or task.get("status") not in {"assigned", "deploying"}:
                raise ValueError("任务与客户端不匹配")
            image_path = Path(str(task.get("image_path") or "")).resolve()
            try:
                image_path.relative_to(IMAGE_DIR.resolve())
            except ValueError as exc:
                raise ValueError("镜像路径越界") from exc
            if not image_path.is_file():
                raise ValueError("下发镜像不存在")
            task["status"] = "deploying"
            task["received_bytes"] = 0
            task["message"] = "正在向客户端下发压缩镜像"
            self._save_tasks(rows)
            return dict(task), image_path

    def complete_deploy(
        self, task_id: str, mac: str,
        identity_ok: bool = True, identity_message: str = "",
    ) -> None:
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task:
                raise ValueError("任务不存在")
            if task.get("action") != "deploy" or task.get("mac") != mac.lower():
                raise ValueError("任务与客户端不匹配")
            if task.get("status") != "deploying":
                raise ValueError("任务不在下发状态")
            source_bytes = int(task.get("source_bytes") or 0)
            started_ts = float(task.get("started_ts") or time.time())
            identity_enabled = bool(task.get("apply_registered_identity"))
            apply_name = bool(task.get("apply_computer_name", identity_enabled))
            apply_ip = bool(task.get("apply_static_ip", identity_enabled))
            network_mode = str(task.get("identity_network_mode") or "")
            if not network_mode:
                network_mode = "static" if apply_ip else "unchanged"
            identity_warning = identity_enabled and not identity_ok
            identity_applied_offline = (
                identity_enabled
                and identity_ok
                and apply_name
                and network_mode == "unchanged"
            )
            task["status"] = "completed_warning" if identity_warning else "completed"
            task["written_bytes"] = source_bytes
            task["received_bytes"] = source_bytes
            task["progress_percent"] = 100.0
            task["elapsed_seconds"] = max(0, int(time.time() - started_ts))
            task["identity_status"] = (
                "failed" if identity_warning else
                (
                    "applied_offline" if identity_applied_offline else
                    ("scheduled" if identity_enabled else "disabled")
                )
            )
            task["identity_message"] = identity_message[:300]
            task["message"] = (
                f"镜像写盘完成，但所选个性化配置未写入：{identity_message}"
                if identity_warning else
                (
                    (
                        f"镜像写盘完成；计算机名已离线写入，网络设置保持原样；"
                        f"耗时 {format_duration(task['elapsed_seconds'])}"
                    )
                    if identity_applied_offline else
                    (
                        f"镜像写盘完成；已写入所选名称/网络配置；"
                        f"耗时 {format_duration(task['elapsed_seconds'])}"
                    )
                    if identity_enabled else
                    f"镜像写盘完成；耗时 {format_duration(task['elapsed_seconds'])}"
                )
            )
            task["completed_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            self._save_tasks(rows)

    def identity_result(
        self, task_id: str, mac: str, ok: bool, message: str,
        actual_name: str = "", actual_ip: str = "",
    ) -> None:
        mac = normalize_mac(mac)
        with self.lock:
            rows = self.tasks()
            task = next((row for row in rows if row.get("id") == task_id), None)
            if not task or task.get("action") != "deploy" or task.get("mac") != mac:
                raise ValueError("个性化结果与客户端任务不匹配")
            if not task.get("apply_registered_identity"):
                raise ValueError("该任务未启用系统个性化")
            task["identity_status"] = "applied" if ok else "failed"
            task["identity_message"] = message[:500]
            task["identity_applied_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if actual_name:
                task["identity_actual_name"] = actual_name[:80]
            if actual_ip:
                task["identity_actual_ip"] = actual_ip[:45]
            if ok:
                task["status"] = "completed"
                applied: list[str] = []
                if bool(task.get("apply_computer_name", True)):
                    applied.append(
                        f"计算机名 {actual_name or task.get('identity_name', '')}"
                    )
                if bool(task.get("apply_static_ip", True)):
                    applied.append(
                        f"固定IP {actual_ip or task.get('identity_ip', '')}"
                    )
                elif task.get("identity_network_mode") == "dhcp":
                    applied.append("IPv4自动获取")
                task["message"] = f"镜像写盘完成；系统已应用：{'，'.join(applied)}"
            else:
                task["status"] = "completed_warning"
                task["message"] = f"镜像写盘完成，但系统个性化执行失败：{message[:300]}"
            self._save_tasks(rows)

    def fail(self, task_id: str, message: str) -> str:
        with self.lock:
            rows = self.tasks()
            selected = next((row for row in rows if row.get("id") == task_id), None)
            session_id = str((selected or {}).get("multicast_session_id") or "")
            for row in rows:
                same_target = row.get("id") == task_id or (
                    session_id and row.get("multicast_session_id") == session_id
                )
                if same_target and row.get("status") not in {"completed", "cancelled"}:
                    row["status"] = "failed"
                    if session_id:
                        row["multicast_state"] = "failed"
                    row["message"] = message[:300]
            self._save_tasks(rows)
            return session_id


class MulticastCoordinator:
    def __init__(self, store: JsonTaskStore, config: dict, log_callback):
        self.store = store
        self.config = config
        self.log_callback = log_callback
        self.lock = threading.RLock()
        self.processes: dict[str, subprocess.Popen | None] = {}
        self.cancel_events: dict[str, threading.Event] = {}

    @staticmethod
    def portbase(session_id: str) -> int:
        return 10000 + (int(session_id[:8], 16) % 2000) * 2

    def sender_path(self) -> Path:
        machine = platform.machine().lower()
        candidates: list[Path] = []
        if os.name == "nt" and machine in {"amd64", "x86_64"}:
            candidates.append(ROOT / "tools" / "udpcast" / "windows-x64" / "udp-sender.exe")
        elif os.name != "nt":
            if machine in {"amd64", "x86_64"}:
                candidates.append(ROOT / "tools" / "udpcast" / "linux-x86_64" / "udp-sender")
            elif machine in {"aarch64", "arm64"}:
                candidates.append(ROOT / "tools" / "udpcast" / "linux-aarch64" / "udp-sender")
            elif machine in {"loongarch64", "loong64"}:
                candidates.append(ROOT / "tools" / "udpcast" / "linux-loongarch64" / "udp-sender")
        system_sender = shutil.which("udp-sender")
        if system_sender:
            candidates.append(Path(system_sender))
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        raise ValueError(
            f"当前管理端架构 {platform.system()}/{platform.machine()} 没有可用的 udp-sender。"
        )

    @staticmethod
    def udpcast_install_command() -> list[str] | None:
        if os.name == "nt":
            return None
        installers = (
            ("apt-get", ["apt-get", "install", "-y", "udpcast"]),
            ("dnf", ["dnf", "install", "-y", "udpcast"]),
            ("yum", ["yum", "install", "-y", "udpcast"]),
            ("zypper", ["zypper", "--non-interactive", "install", "udpcast"]),
        )
        for exe, cmd in installers:
            if shutil.which(exe):
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    return cmd
                sudo = shutil.which("sudo")
                if sudo:
                    return [sudo, *cmd]
                pkexec = shutil.which("pkexec")
                if pkexec:
                    return [pkexec, *cmd]
                return None
        return None

    def install_udpcast(self) -> tuple[bool, str]:
        cmd = self.udpcast_install_command()
        if not cmd:
            return False, "没有检测到可用的软件包管理器或提权工具。"
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=180, check=False,
            )
        except Exception as exc:
            return False, str(exc)
        if result.returncode != 0:
            detail = (result.stdout or "").strip()[-1200:]
            return False, detail or f"安装命令退出码 {result.returncode}"
        try:
            self.sender_path()
        except ValueError:
            return False, "udpcast 安装完成，但仍未找到 udp-sender。"
        return True, "udpcast 已安装，可以使用组播。"

    def prepare(self, task_id: str, mac: str) -> dict:
        summary = self.store.multicast_ready(task_id, mac)
        session_id = summary["session_id"]
        if summary["should_start"]:
            self.start(session_id)
        return self.status(session_id)

    @staticmethod
    def protocol(summary: dict) -> str:
        source_architectures = {
            normalize_architecture(str(row.get("source_arch") or ""))
            for row in summary.get("rows") or []
        }
        source_architectures.discard("unknown")
        architectures = {
            normalize_architecture(str(row.get("client_arch") or ""))
            for row in summary.get("rows") or []
        }
        architectures.discard("unknown")
        # ARM64 and LoongArch64 PXE environments ship the architecture-neutral
        # ZOSMC receiver, so they never depend on an Internet-installed udpcast.
        # Mixed ARM64/LoongArch64 groups are also transport-compatible; image/CPU
        # mismatch remains a warn-only administrator choice at task creation.
        if architectures in ({"arm64"}, {"loongarch64"}):
            return "zosmc1"
        if "loongarch64" in architectures and len(architectures) > 1:
            raise ValueError("组播会话不能混合龙芯与其他CPU架构")
        if source_architectures and source_architectures.issubset({"arm64", "loongarch64"}):
            # Old registrations may not yet have client_arch; use image/source arch
            # as a safe compatibility fallback for the first upgraded boot.
            return "zosmc1"
        return "udpcast"

    def status(self, session_id: str) -> dict:
        summary = self.store.multicast_session(session_id)
        protocol = self.protocol(summary)
        summary.pop("rows", None)
        summary["portbase"] = self.portbase(session_id)
        summary["server_ip"] = str(self.config["pxe_server_ip"])
        summary["protocol"] = protocol
        summary["multicast_group"] = (
            group_for_session(session_id) if protocol == "zosmc1" else ""
        )
        return summary

    def start(self, session_id: str) -> None:
        summary = self.store.multicast_session(session_id)
        protocol = self.protocol(summary)
        sender = self.sender_path() if protocol == "udpcast" else None
        with self.lock:
            if session_id in self.processes:
                return
            self.processes[session_id] = None
            cancel_event = threading.Event()
            self.cancel_events[session_id] = cancel_event
        target = self._run_zos_sender if protocol == "zosmc1" else self._run_sender
        args = (session_id, cancel_event) if protocol == "zosmc1" else (
            session_id, sender
        )
        thread = threading.Thread(
            target=target,
            args=args,
            daemon=True,
            name=f"zos-multicast-{session_id}",
        )
        thread.start()

    def _run_zos_sender(self, session_id: str, cancel_event: threading.Event) -> None:
        try:
            summary = self.store.multicast_session(session_id)
            image_path = Path(summary["image_path"]).resolve()
            image_path.relative_to(IMAGE_DIR.resolve())
            if not image_path.is_file():
                raise ValueError("ZOS可靠组播镜像文件不存在")
            rows = summary["rows"]
            expected_macs = [str(row.get("mac") or "") for row in rows]
            if not all(expected_macs):
                raise ValueError("ZOS可靠组播任务缺少客户端MAC")
            profile = normalize_multicast_profile(
                str(rows[0].get("multicast_profile") or "gigabit")
            )
            portbase = self.portbase(session_id)
            expected = int(summary["expected"])
            self.store.set_multicast_state(
                session_id, "starting",
                f"等待 {expected} 台ZOS接收器完成可靠组播握手；"
                f"组 {group_for_session(session_id)}，UDP {portbase}/{portbase + 1}",
            )

            def state(message: str) -> None:
                if message == "all_receivers_connected":
                    self.store.set_multicast_state(
                        session_id, "running",
                        f"ZOS可靠组播进行中：{expected}台，{multicast_profile_text(profile)}，"
                        f"UDP {portbase}/{portbase + 1}",
                    )
                elif message.startswith("龙芯接收器握手") or message.startswith("ZOS接收器握手"):
                    self.store.set_multicast_state(session_id, "starting", message)

            self.log_callback(
                f"ZOS可靠组播准备：会话 {session_id}，{expected}台，"
                f"{group_for_session(session_id)}，UDP {portbase}/{portbase + 1}"
            )
            send_zos_multicast(
                image_path=image_path,
                session_id=session_id,
                server_ip=str(self.config["pxe_server_ip"]),
                data_port=portbase,
                expected_macs=expected_macs,
                profile=profile,
                start_timeout=max(10, min(300, int(self.config.get("zosmc_handshake_timeout", 60)))),
                cancel_event=cancel_event,
                state_callback=state,
            )
            self.store.set_multicast_state(
                session_id, "sent", "ZOS组播数据及SHA-256校验完成，等待客户端写盘确认"
            )
            self.log_callback(f"ZOS可靠组播发送完成：会话 {session_id}")
        except Exception as exc:
            self.store.set_multicast_state(session_id, "failed", f"ZOS组播失败：{exc}")
            self.log_callback(f"ZOS可靠组播失败：会话 {session_id}，{exc}")
        finally:
            with self.lock:
                self.processes.pop(session_id, None)
                self.cancel_events.pop(session_id, None)

    def _run_sender(self, session_id: str, sender: Path) -> None:
        process = None
        try:
            summary = self.store.multicast_session(session_id)
            image_path = Path(summary["image_path"]).resolve()
            image_path.relative_to(IMAGE_DIR.resolve())
            if not image_path.is_file():
                raise ValueError("组播镜像文件不存在")
            expected = int(summary["expected"])
            profile = normalize_multicast_profile(
                str(summary["rows"][0].get("multicast_profile") or "gigabit")
            )
            profile_args = {
                "compatible": [
                    "--min-slice-size", "32",
                    "--max-slice-size", "256",
                    "--slice-size", "64",
                    "--retries-until-drop", "500",
                ],
                "gigabit": [
                    "--min-slice-size", "128",
                    "--max-slice-size", "1024",
                    "--slice-size", "256",
                    "--retries-until-drop", "200",
                ],
                "maximum": [
                    "--min-slice-size", "256",
                    "--max-slice-size", "1024",
                    "--slice-size", "512",
                    "--retries-until-drop", "100",
                ],
            }[profile]
            portbase = self.portbase(session_id)
            command = [
                str(sender),
                "--file", str(image_path),
                "--interface", str(self.config["pxe_server_ip"]),
                "--portbase", str(portbase),
                "--min-receivers", str(expected),
                "--min-wait", "2",
                "--autostart", "1",
                "--start-timeout", str(int(self.config.get("multicast_start_timeout", 900))),
                "--blocksize", "1456",
                "--full-duplex",
                *profile_args,
                "--nopointopoint",
                "--nokbd",
            ]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=creationflags,
            )
            with self.lock:
                self.processes[session_id] = process
            self.store.set_multicast_state(
                session_id, "running",
                f"可靠组播进行中：{expected}台，{multicast_profile_text(profile)}，"
                f"UDP端口 {portbase}/{portbase + 1}",
            )
            self.log_callback(
                f"ZOS组播已启动：会话 {session_id}，{expected}台，"
                f"{multicast_profile_text(profile)}，{image_path.name}，"
                f"UDP {portbase}/{portbase + 1}"
            )
            output_tail: list[str] = []
            if process.stdout:
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        output_tail = (output_tail + [line])[-8:]
            return_code = process.wait()
            if return_code != 0:
                detail = "；".join(output_tail)[-240:]
                raise RuntimeError(f"udp-sender退出码 {return_code}：{detail}")
            self.store.set_multicast_state(
                session_id, "sent", "组播数据发送完成，等待各客户端写盘确认"
            )
            self.log_callback(f"ZOS组播发送完成：会话 {session_id}")
        except Exception as exc:
            self.store.set_multicast_state(session_id, "failed", f"组播失败：{exc}")
            self.log_callback(f"ZOS组播失败：会话 {session_id}，{exc}")
        finally:
            with self.lock:
                self.processes.pop(session_id, None)
                self.cancel_events.pop(session_id, None)

    def stop_all(self) -> None:
        with self.lock:
            processes = [process for process in self.processes.values() if process]
            cancel_events = list(self.cancel_events.values())
        for event in cancel_events:
            event.set()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()

    def stop_session(self, session_id: str) -> None:
        if not session_id:
            return
        with self.lock:
            process = self.processes.get(session_id)
            cancel_event = self.cancel_events.get(session_id)
        if cancel_event:
            cancel_event.set()
        if process and process.poll() is None:
            process.terminate()


class UploadHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline(1024 * 1024)
            if not line.endswith(b"\n"):
                raise ValueError("请求头过长或不完整")
            request = json.loads(line.decode("utf-8"))
            if not hmac.compare_digest(str(request.get("token", "")), self.server.agent_token):
                raise ValueError("令牌错误")
            operation = request.get("op")
            if operation == "groups":
                self._reply({"ok": True, **self.server.group_provider()})
                return
            if operation == "register":
                group_info = self.server.group_provider()
                groups = normalize_group_list(group_info.get("groups"))
                requested_group = normalize_group_name(
                    str(request.get("group") or group_info.get("default_group") or groups[0])
                )
                if requested_group not in groups:
                    raise ValueError("客户端选择的分组不在管理端分组列表中")
                request["group"] = requested_group
                client = self.server.store.register_client(request)
                self._reply({"ok": True, "client": client})
                return
            if operation == "claim":
                task = self.server.store.claim(request)
                self._reply({"ok": True, "task": task})
                return
            if operation == "multicast_ready":
                task_id = str(request.get("task_id", ""))
                mac = str(request.get("mac", "")).lower()
                result = self.server.multicast.prepare(task_id, mac)
                self._reply({"ok": True, **result})
                return
            if operation == "multicast_status":
                task_id = str(request.get("task_id", ""))
                mac = normalize_mac(str(request.get("mac", "")))
                task = next(
                    (row for row in self.server.store.tasks() if row.get("id") == task_id),
                    None,
                )
                if not task or task.get("mac") != mac:
                    raise ValueError("组播任务与客户端不匹配")
                result = self.server.multicast.status(
                    str(task.get("multicast_session_id") or "")
                )
                self._reply({"ok": True, **result})
                return
            if operation == "fail":
                session_id = self.server.store.fail(
                    str(request.get("task_id", "")),
                    str(request.get("message", "客户端失败")),
                )
                self.server.multicast.stop_session(session_id)
                self._reply({"ok": True})
                return
            if operation == "deploy_started":
                self.server.store.deploy_started(
                    str(request.get("task_id", "")),
                    str(request.get("mac", "")).lower(),
                )
                self._reply({"ok": True})
                return
            if operation == "deploy_progress":
                self.server.store.deploy_progress(
                    str(request.get("task_id", "")),
                    str(request.get("mac", "")).lower(),
                    int(request.get("written_bytes", 0)),
                )
                self._reply({"ok": True})
                return
            if operation == "identity_result":
                self.server.store.identity_result(
                    str(request.get("task_id", "")),
                    str(request.get("mac", "")).lower(),
                    bool(request.get("ok", False)),
                    str(request.get("message", "")),
                    str(request.get("actual_name", "")),
                    str(request.get("actual_ip", "")),
                )
                self._reply({"ok": True})
                return
            if operation == "download":
                task_id = str(request.get("task_id", ""))
                mac = str(request.get("mac", "")).lower()
                _task, image_path = self.server.store.begin_download(task_id, mac)
                sent = 0
                last_update = 0.0
                with image_path.open("rb") as source:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        self.wfile.write(block)
                        sent += len(block)
                        now = time.monotonic()
                        if now - last_update >= 1:
                            self.server.store.progress(task_id, sent)
                            last_update = now
                self.wfile.flush()
                self.server.store.progress(task_id, sent)
                return
            if operation == "complete":
                self.server.store.complete_deploy(
                    str(request.get("task_id", "")),
                    str(request.get("mac", "")).lower(),
                    bool(request.get("identity_ok", True)),
                    str(request.get("identity_message", "")),
                )
                self._reply({"ok": True})
                return
            if operation != "upload":
                raise ValueError("不支持的操作")
            task_id = str(request.get("task_id", ""))
            mac = str(request.get("mac", "")).lower()
            _task, partial = self.server.store.begin_upload(
                task_id, mac, int(request.get("source_bytes", 0)),
                str(request.get("device", "")),
                str(request.get("image_type", "")),
                str(request.get("filesystem", "auto")),
                str(request.get("source_arch", "unknown")),
            )
            digest = hashlib.sha256()
            received = 0
            last_update = 0.0
            with partial.open("wb") as output:
                while True:
                    block = self.rfile.read(1024 * 1024)
                    if not block:
                        break
                    output.write(block)
                    digest.update(block)
                    received += len(block)
                    now = time.monotonic()
                    if now - last_update >= 1:
                        self.server.store.progress(task_id, received)
                        last_update = now
            if received == 0:
                raise ValueError("客户端没有上传任何镜像数据")
            target = self.server.store.complete(task_id, partial, received, digest.hexdigest())
            self._reply({"ok": True, "bytes": received, "sha256": digest.hexdigest(), "path": str(target)})
        except Exception as exc:
            try:
                task_id = str(locals().get("request", {}).get("task_id", ""))
                if task_id:
                    session_id = self.server.store.fail(task_id, str(exc))
                    self.server.multicast.stop_session(session_id)
                self._reply({"ok": False, "error": str(exc)})
            except OSError:
                pass

    def _reply(self, value: dict) -> None:
        self.wfile.write(json.dumps(value, ensure_ascii=False).encode("utf-8") + b"\n")
        self.wfile.flush()


class UploadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self, address, store: JsonTaskStore, agent_token: str,
        group_provider, multicast: MulticastCoordinator,
    ):
        self.store = store
        self.agent_token = agent_token
        self.group_provider = group_provider
        self.multicast = multicast
        super().__init__(address, UploadHandler)


class RegistrationDialog(QDialog):
    def __init__(self, store: JsonTaskStore, groups: list[str], selected_mac: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置选中客户端任务（上传/下发）")
        self.resize(680, 380)
        form = QFormLayout(self)
        self.known = QComboBox()
        clients: dict[str, dict] = {}
        for item in read_json(NODE_FILE, []) + store.registrations():
            mac = str(item.get("mac") or "").lower()
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                clients[mac] = {**clients.get(mac, {}), **item}
        self.client_rows = clients
        self.known.addItem("手工填写MAC地址", "")
        for mac, item in sorted(clients.items()):
            name = item.get("name") or item.get("hostname") or "未命名"
            ip = item.get("ip") or ""
            self.known.addItem(f"{name}　{mac}　{ip}", mac)
        self.mac = QLineEdit()
        self.name = QLineEdit()
        self.group = QComboBox()
        for group in groups:
            self.group.addItem(group, group)
        self.action = QComboBox()
        self.action.addItem("不创建任务；无任务时倒计时从本地启动", "manual")
        self.action.addItem("下次开机自动上传模板", "capture")
        self.action.addItem("下次开机自动下发镜像", "deploy")
        self.template = QLineEdit("{hostname}-{date}")
        self.image = QComboBox()
        for path in sorted(IMAGE_DIR.glob("*.img.zst")):
            self.image.addItem(path.name, path.name)
        self.device = QLineEdit("auto")
        self.apply_name = QCheckBox("按注册客户端名称修改计算机名")
        self.apply_ip = QCheckBox("按注册客户端IP设置固定IPv4")
        self.post_action = QComboBox()
        fill_post_actions(self.post_action)
        self.known.currentIndexChanged.connect(self.load_known)
        self.action.currentIndexChanged.connect(self.update_task_options)
        form.addRow("已发现/已注册客户端：", self.known)
        form.addRow("客户端MAC：", self.mac)
        form.addRow("客户端名称：", self.name)
        form.addRow("客户端分组：", self.group)
        form.addRow("下次开机动作：", self.action)
        form.addRow("上传模板名称：", self.template)
        form.addRow("下发镜像：", self.image)
        form.addRow("源盘/目标盘：", self.device)
        form.addRow("计算机名：", self.apply_name)
        form.addRow("固定IP：", self.apply_ip)
        form.addRow("任务成功后：", self.post_action)
        note = QLabel(
            "上传和下发任务只执行一次并绑定此MAC，其他客户端不能领取。"
            "“修改计算机名”和“设置固定IP”可分别勾选。未勾选计算机名时保留镜像名称；"
            "未勾选固定IP时保留镜像网络设置（通常为DHCP自动获取）。Windows 7及以上"
            "无需安装客户端；固定IP按注册MAC设置，成功后移除一次性启动项。"
        )
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        if selected_mac:
            index = self.known.findData(selected_mac)
            if index >= 0:
                self.known.setCurrentIndex(index)
                self.load_known(index)
        self.update_task_options()

    def load_known(self, _index=0):
        mac = str(self.known.currentData() or "")
        if not mac:
            return
        item = self.client_rows.get(mac, {})
        self.mac.setText(mac)
        self.name.setText(str(item.get("name") or item.get("hostname") or ""))
        group = normalize_group_name(str(item.get("group") or "默认组"))
        index = self.group.findData(group)
        if index < 0:
            self.group.addItem(group, group)
            index = self.group.findData(group)
        self.group.setCurrentIndex(index)

    def update_task_options(self, _index=0):
        is_deploy = self.action.currentData() == "deploy"
        self.apply_name.setEnabled(is_deploy)
        self.apply_ip.setEnabled(is_deploy)
        if not is_deploy:
            self.apply_name.setChecked(False)
            self.apply_ip.setChecked(False)


class GroupTaskDialog(QDialog):
    def __init__(self, group: str, client_count: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"设置分组任务：{group}")
        self.resize(680, 360)
        form = QFormLayout(self)
        self.action = QComboBox()
        self.action.addItem("组内客户端分别上传模板", "capture")
        self.action.addItem("向组内客户端部署同一镜像", "deploy")
        self.template = QLineEdit("{group}-{hostname}-{date}")
        self.image = QComboBox()
        for path in sorted(IMAGE_DIR.glob("*.img.zst")):
            self.image.addItem(path.name, path.name)
        self.device = QLineEdit("auto")
        self.transfer_mode = QComboBox()
        self.transfer_mode.addItem("单独下发（每台客户端独立TCP传输）", "unicast")
        self.transfer_mode.addItem("组播同步下发（全组上线后统一发送）", "multicast")
        self.multicast_profile = QComboBox()
        self.multicast_profile.addItem("千兆高速（推荐）", "gigabit")
        self.multicast_profile.addItem("兼容稳定（老交换机/丢包网络）", "compatible")
        self.multicast_profile.addItem("高速网络/SSD（更激进）", "maximum")
        self.apply_name = QCheckBox("按每台注册名称修改计算机名")
        self.apply_ip = QCheckBox("按每台注册IP设置固定IPv4")
        self.post_action = QComboBox()
        fill_post_actions(self.post_action)
        self.action.currentIndexChanged.connect(self.update_transfer_mode)
        self.transfer_mode.currentIndexChanged.connect(self.update_transfer_mode)
        form.addRow("目标分组：", QLabel(f"{group}（{client_count}台）"))
        form.addRow("任务类型：", self.action)
        form.addRow("上传镜像名称：", self.template)
        form.addRow("下发镜像：", self.image)
        form.addRow("下发方式：", self.transfer_mode)
        form.addRow("组播速度：", self.multicast_profile)
        form.addRow("源盘/目标盘：", self.device)
        form.addRow("计算机名：", self.apply_name)
        form.addRow("固定IP：", self.apply_ip)
        form.addRow("任务成功后：", self.post_action)
        note = QLabel(
            "单独下发：每台客户端独立传输，互不等待。"
            "组播同步：必须等本组任务中的所有客户端都启动并完成磁盘检查，才统一写盘；"
            "x86/ARM使用UDPcast；龙芯使用内置ZOSMC1窗口确认和丢包补发。"
            "计算机名和固定IP可分别勾选；每台电脑仍按自身MAC取得对应注册信息。"
            "未勾选固定IP时保留DHCP自动获取；Windows 7及以上无需预装客户端。上传任务仍是每台独立上传，"
            "镜像名称会替换 {group}、{hostname}、{mac}、{date}。"
        )
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)
        self.update_transfer_mode()

    def update_transfer_mode(self, _index=0):
        is_deploy = self.action.currentData() == "deploy"
        self.transfer_mode.setEnabled(is_deploy)
        is_multicast = is_deploy and self.transfer_mode.currentData() == "multicast"
        self.multicast_profile.setEnabled(is_multicast)
        self.apply_name.setEnabled(is_deploy)
        self.apply_ip.setEnabled(is_deploy)
        if not is_deploy:
            self.transfer_mode.setCurrentIndex(0)
            self.apply_name.setChecked(False)
            self.apply_ip.setChecked(False)


class ClientIdentityEditDialog(QDialog):
    """Edit one client directly, or generate sequential names/IPs for a selection."""

    def __init__(self, clients: list[dict], subnet_mask: str, parent=None):
        super().__init__(parent)
        self.clients = [dict(row) for row in clients]
        self.subnet_mask = str(subnet_mask or "255.255.255.0")
        self._updates: list[dict] = []
        self.single = len(self.clients) == 1
        self.setWindowTitle(
            "修改客户端IP和计算机名" if self.single
            else f"批量修改IP和计算机名（{len(self.clients)}台）"
        )
        self.resize(610, 330 if self.single else 445)
        form = QFormLayout(self)

        self.apply_name = QCheckBox(
            "修改这台客户端的名称/计算机名" if self.single
            else "按顺序批量修改名称/计算机名"
        )
        self.apply_ip = QCheckBox(
            "修改这台客户端的注册IP" if self.single
            else "从起始IP开始连续分配"
        )
        self.apply_name.setChecked(True)
        self.apply_ip.setChecked(True)
        form.addRow("修改项目：", self.apply_name)
        form.addRow("", self.apply_ip)

        first = self.clients[0] if self.clients else {}
        if self.single:
            form.addRow("客户端MAC：", QLabel(str(first.get("mac") or "")))
            self.name_value = QLineEdit(str(first.get("name") or ""))
            self.ip_value = QLineEdit(str(first.get("ip") or ""))
            self.ip_value.setPlaceholderText("可留空；留空表示不保存固定注册IP")
            form.addRow("名称/计算机名：", self.name_value)
            form.addRow("注册IP：", self.ip_value)
            self.apply_name.stateChanged.connect(
                lambda _state: self.name_value.setEnabled(self.apply_name.isChecked())
            )
            self.apply_ip.stateChanged.connect(
                lambda _state: self.ip_value.setEnabled(self.apply_ip.isChecked())
            )
        else:
            inferred_prefix = "ZOS-"
            inferred_start = 1
            inferred_digits = 3
            match = re.fullmatch(r"(.*?)(\d+)", str(first.get("name") or ""))
            if match:
                inferred_prefix = match.group(1)
                inferred_start = int(match.group(2))
                inferred_digits = max(1, len(match.group(2)))
            self.name_prefix = QLineEdit(inferred_prefix)
            self.name_start = QLineEdit(str(inferred_start))
            self.name_digits = QLineEdit(str(inferred_digits))
            self.ip_start = QLineEdit(str(first.get("ip") or ""))
            self.ip_start.setPlaceholderText("例如 192.168.5.101")
            self.assignment_order = QComboBox()
            self.assignment_order.addItem("正序（当前列表从上到下）", "forward")
            self.assignment_order.addItem("倒序（当前列表从下到上）", "reverse")
            form.addRow("名称前缀：", self.name_prefix)
            form.addRow("起始编号：", self.name_start)
            form.addRow("编号位数：", self.name_digits)
            form.addRow("起始IP：", self.ip_start)
            form.addRow("分配方向：", self.assignment_order)
            order = QLabel(
                "先点击客户端列表标题完成排序，再选择需要修改的客户端。正序把起始编号/IP分配给"
                "当前列表最上方的选中客户端；倒序则从最下方开始分配。"
            )
            order.setWordWrap(True)
            form.addRow("批量规则：", order)
            for widget in (self.name_prefix, self.name_start, self.name_digits):
                self.apply_name.stateChanged.connect(
                    lambda _state, target=widget: target.setEnabled(self.apply_name.isChecked())
                )
            self.apply_ip.stateChanged.connect(
                lambda _state: self.ip_start.setEnabled(self.apply_ip.isChecked())
            )

        note = QLabel(
            "这里的IP和名称是已注册客户端的统一身份信息。新建或尚未领取的镜像任务会同步更新；"
            "客户端PXE启动时临时获得的地址只作为在线通信地址，不再覆盖这里的注册IP。"
            "正在写盘或已经完成的历史任务不会被反向修改。"
        )
        note.setWordWrap(True)
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def build_updates(self) -> list[dict]:
        if not self.clients:
            raise ValueError("没有选中客户端")
        change_name = self.apply_name.isChecked()
        change_ip = self.apply_ip.isChecked()
        if not change_name and not change_ip:
            raise ValueError("请至少勾选一个修改项目")

        direction = (
            self.assignment_order.currentData()
            if not self.single else "forward"
        )
        ordered_clients = clients_in_batch_direction(self.clients, direction)

        generated_names: list[str] = []
        generated_ips: list[str] = []
        if change_name:
            if self.single:
                name = self.name_value.text().strip()
                if not name:
                    raise ValueError("名称/计算机名不能为空")
                generated_names = [name[:80]]
            else:
                try:
                    start = int(self.name_start.text().strip())
                    digits = int(self.name_digits.text().strip())
                except ValueError as exc:
                    raise ValueError("起始编号和编号位数必须是整数") from exc
                if start < 0:
                    raise ValueError("起始编号不能小于0")
                if not 1 <= digits <= 10:
                    raise ValueError("编号位数应为1到10")
                prefix = self.name_prefix.text().strip()
                generated_names = [
                    f"{prefix}{start + index:0{digits}d}"[:80]
                    for index in range(len(ordered_clients))
                ]
                if len(set(generated_names)) != len(generated_names):
                    raise ValueError("生成的客户端名称存在重复，请调整前缀或编号")

        if change_ip:
            if self.single:
                raw = self.ip_value.text().strip()
                generated_ips = [str(ipaddress.IPv4Address(raw)) if raw else ""]
            else:
                raw = self.ip_start.text().strip()
                if not raw:
                    raise ValueError("批量修改IP时必须填写起始IP")
                start_ip = ipaddress.IPv4Address(raw)
                try:
                    network = ipaddress.IPv4Network(
                        f"{start_ip}/{self.subnet_mask}", strict=False
                    )
                except ValueError as exc:
                    raise ValueError("当前子网掩码无效，不能批量连续分配IP") from exc
                generated_ips = []
                for index in range(len(ordered_clients)):
                    try:
                        address = ipaddress.IPv4Address(int(start_ip) + index)
                    except ipaddress.AddressValueError as exc:
                        raise ValueError("批量IP超出IPv4地址范围") from exc
                    if address not in network or address in {
                        network.network_address, network.broadcast_address,
                    }:
                        raise ValueError(
                            f"批量IP {address} 已超出当前子网可用主机地址范围"
                        )
                    generated_ips.append(str(address))

        updates: list[dict] = []
        for index, client in enumerate(ordered_clients):
            updates.append({
                "mac": str(client.get("mac") or ""),
                "name": (
                    generated_names[index] if change_name
                    else str(client.get("name") or "")
                ),
                "ip": (
                    generated_ips[index] if change_ip
                    else str(client.get("ip") or "")
                ),
            })
        return updates

    def accept(self):
        try:
            self._updates = self.build_updates()
        except ValueError as exc:
            QMessageBox.warning(self, "修改内容无效", str(exc))
            return
        super().accept()

    def result_updates(self) -> list[dict]:
        return [dict(row) for row in self._updates]


MODERN_STYLE = """
QMainWindow, QWidget#appRoot {
    background: #eef2fa;
    color: #273655;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 13px;
}
QFrame#sidebar {
    background: #3d4e7d;
    border: none;
}
QLabel#brand {
    color: white;
    font-size: 22px;
    font-weight: 700;
    letter-spacing: 2px;
}
QLabel#versionBadge {
    color: #dce4ff;
    background: #526497;
    border-radius: 10px;
    padding: 5px 10px;
}
QLabel#navLabel {
    color: #e4e9fb;
    padding: 10px 7px;
    font-size: 14px;
}
QLabel#serviceStatus {
    color: #dce4ff;
    background: #33436e;
    border-radius: 8px;
    padding: 10px;
}
QLabel#pageTitle {
    color: #263b78;
    font-size: 24px;
    font-weight: 700;
}
QLabel#pageSubtitle, QLabel#storageHint {
    color: #8792ad;
}
QLabel#summaryBadge {
    color: #40538d;
    background: white;
    border: 1px solid #dce3f2;
    border-radius: 16px;
    padding: 7px 14px;
    font-weight: 600;
}
QFrame#card {
    background: white;
    border: 1px solid #dfe5f2;
    border-radius: 9px;
}
QLabel#sectionTitle {
    color: #2c407b;
    font-size: 15px;
    font-weight: 700;
}
QLineEdit, QComboBox {
    background: #f8faff;
    color: #263655;
    border: 1px solid #d4dced;
    border-radius: 6px;
    min-height: 30px;
    padding: 1px 8px;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #6075b8;
    background: white;
}
QPushButton {
    color: #40517f;
    background: #eef2fb;
    border: 1px solid #d5ddef;
    border-radius: 6px;
    min-height: 30px;
    padding: 1px 11px;
    font-weight: 600;
}
QPushButton:hover { background: #e2e8f8; border-color: #aebbdc; }
QPushButton:pressed { background: #d8e0f3; }
QPushButton#primaryButton {
    color: white;
    background: #5268a6;
    border-color: #5268a6;
}
QPushButton#primaryButton:hover { background: #465b98; }
QPushButton#accentButton {
    color: white;
    background: #ff3f86;
    border: none;
    min-height: 38px;
}
QPushButton#accentButton:hover { background: #ed2f77; }
QPushButton#sidebarButton {
    color: white;
    background: #516394;
    border: 1px solid #6f80ad;
    min-height: 36px;
}
QPushButton#dangerButton {
    color: #c83b58;
    background: #fff1f4;
    border-color: #f4c6d0;
}
QPushButton#dangerButton:hover { color: white; background: #db4563; }
QTableWidget#dataTable {
    background: white;
    alternate-background-color: #f7f9fd;
    border: 1px solid #e1e6f1;
    border-radius: 5px;
    gridline-color: #edf0f6;
    selection-background-color: #dce6ff;
    selection-color: #20366e;
}
QTableWidget#dataTable::item { padding: 5px; }
QHeaderView::section {
    background: #edf2fb;
    color: #354875;
    border: none;
    border-right: 1px solid #dce3f0;
    border-bottom: 1px solid #d5ddec;
    padding: 7px 6px;
    font-weight: 700;
}
QTextEdit#serviceLog {
    color: #dbe5ff;
    background: #263552;
    border: none;
    border-radius: 6px;
    font-family: Consolas, "Microsoft YaHei";
    font-size: 12px;
}
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #b8c3dc; border-radius: 5px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
"""



class ImageCatalogDialog(QDialog):
    def __init__(self, catalog: list[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle("镜像库")
        self.resize(980, 520)
        layout = QVBoxLayout(self)
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索镜像名称、架构、标签或备注")
        refresh = QPushButton("刷新")
        open_dir = QPushButton("打开镜像目录")
        tools.addWidget(self.search, 1)
        tools.addWidget(refresh)
        tools.addWidget(open_dir)
        layout.addLayout(tools)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(["镜像", "架构", "类型", "源容量", "压缩大小", "创建时间", "标签", "备注"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        layout.addWidget(self.table)
        self.catalog = catalog
        self.search.textChanged.connect(self.refresh_rows)
        refresh.clicked.connect(self.reload)
        open_dir.clicked.connect(self.open_directory)
        self.refresh_rows()

    def reload(self):
        self.catalog = rebuild_image_catalog()
        self.refresh_rows()

    def refresh_rows(self):
        key = self.search.text().strip().lower()
        rows = []
        for row in self.catalog:
            text = " ".join([
                str(row.get("name") or ""), str(row.get("architecture") or ""),
                str(row.get("image_type") or ""), " ".join(map(str, row.get("tags") or [])),
                str(row.get("note") or "")
            ]).lower()
            if not key or key in text:
                rows.append(row)
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            source = int(row.get("source_bytes") or 0)
            compressed = int(row.get("compressed_bytes") or 0)
            values = [
                row.get("name") or row.get("file") or "",
                row.get("architecture") or "unknown",
                row.get("image_type") or "unknown",
                f"{source / 1024 / 1024 / 1024:.1f} GiB" if source else "-",
                f"{compressed / 1024 / 1024:.1f} MiB",
                row.get("created_at") or "",
                ", ".join(map(str, row.get("tags") or [])),
                row.get("note") or "",
            ]
            for c, value in enumerate(values):
                self.table.setItem(r, c, QTableWidgetItem(str(value)))

    def open_directory(self):
        path = str(IMAGE_DIR.resolve())
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception as exc:
            QMessageBox.warning(self, "打开失败", str(exc))


class PreflightDialog(QDialog):
    def __init__(self, config: dict, pxe, catalog: list[dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle("部署环境自检")
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        layout.addWidget(self.text)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.run_checks(config, pxe, catalog)

    def run_checks(self, config, pxe, catalog):
        results = []
        def add(ok, title, detail=""):
            results.append(("✓" if ok else "✗", title, detail))
        add(IMAGE_DIR.is_dir(), "镜像目录", str(IMAGE_DIR))
        add(bool(catalog), "镜像文件", f"共 {len(catalog)} 个 .img.zst 镜像")
        tftp_root = Path(str(config.get("tftp_root") or ""))
        add(tftp_root.is_dir(), "TFTP 目录", str(tftp_root))
        required = ["undionly.kpxe", "ipxe.efi", "ipxe-arm64.efi", "ipxe-loongarch64.efi"]
        missing = [name for name in required if not (tftp_root / name).exists()]
        add(not missing, "多架构 PXE 文件", "正常" if not missing else "缺少：" + ", ".join(missing))
        server_ip = str(config.get("pxe_server_ip") or "").strip()
        try:
            ipaddress.ip_address(server_ip)
            add(True, "服务器 IP", server_ip)
        except ValueError:
            add(False, "服务器 IP", f"无效：{server_ip}")
        try:
            net = ipaddress.ip_network(f"{server_ip}/{config.get('dhcp_subnet_mask')}", strict=False)
            start = ipaddress.ip_address(str(config.get("dhcp_pool_start")))
            end = ipaddress.ip_address(str(config.get("dhcp_pool_end")))
            add(start in net and end in net and int(start) <= int(end), "DHCP 地址池", f"{start} - {end}")
        except Exception as exc:
            add(False, "DHCP 地址池", str(exc))
        try:
            free = shutil.disk_usage(ROOT).free
            add(free >= 5 * 1024**3, "管理端磁盘空间", f"剩余 {free / 1024**3:.1f} GiB")
        except Exception as exc:
            add(False, "管理端磁盘空间", str(exc))
        interfaces = pxe.interfaces()
        add(bool(interfaces), "部署网卡", "已发现 %d 个可用网卡" % len(interfaces))
        selected = str(config.get("pxe_interface_name") or "")
        add(any(i.get("name") == selected for i in interfaces) if selected else bool(interfaces), "当前网卡", selected or "将使用首个可用网卡")
        lines = ["部署前快速检查", ""]
        for icon, title, detail in results:
            lines.append(f"{icon} {title}：{detail}")
        bad = sum(1 for icon, *_ in results if icon == "✗")
        lines += ["", "结果：" + ("可以开始部署" if bad == 0 else f"发现 {bad} 项需要处理")]
        self.text.setPlainText("\n".join(lines))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"菁云镜像部署系统 {VERSION}（无HTTP/无数据库）")
        self.image_catalog = rebuild_image_catalog()
        self.resize(1420, 900)
        self.setMinimumSize(1120, 760)
        self.config = default_config()
        self.config.update(read_json(CONFIG_FILE, {}))
        self.store = JsonTaskStore()
        self.pxe = PxeController(self.config, CONFIG_FILE)
        self.multicast = MulticastCoordinator(self.store, self.config, self.pxe.log)
        self.upload_server: UploadServer | None = None
        self.upload_thread: threading.Thread | None = None
        self._build()
        self.refresh_nics()
        self.refresh_view()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start(1000)

    def _build(self):
        root = QWidget()
        root.setObjectName("appRoot")
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(205)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(22, 28, 22, 24)
        side.setSpacing(12)
        brand = QLabel("JINGYUN\nZOS DEPLOY")
        brand.setObjectName("brand")
        side.addWidget(brand)
        version = QLabel(f"VERSION  {VERSION}")
        version.setObjectName("versionBadge")
        side.addWidget(version)
        side.addSpacing(22)
        for text in ("▣  设备中心", "◆  镜像任务", "≡  服务日志"):
            label = QLabel(text)
            label.setObjectName("navLabel")
            side.addWidget(label)
        side.addStretch()
        self.status = QLabel("服务未启动")
        self.status.setObjectName("serviceStatus")
        self.status.setWordWrap(True)
        side.addWidget(self.status)
        self.start_button = QPushButton("开启 PXE + DHCP")
        self.start_button.setObjectName("accentButton")
        self.stop_button = QPushButton("停止服务")
        self.stop_button.setObjectName("sidebarButton")
        self.start_button.clicked.connect(self.start_services)
        self.stop_button.clicked.connect(self.stop_services)
        side.addWidget(self.start_button)
        side.addWidget(self.stop_button)
        shell.addWidget(sidebar)

        main = QWidget()
        layout = QVBoxLayout(main)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(12)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("设备与镜像中心")
        title.setObjectName("pageTitle")
        subtitle = QLabel("集中管理 PXE、客户端注册、镜像上传与批量部署")
        subtitle.setObjectName("pageSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)
        header.addStretch()
        self.header_summary = QLabel("客户端 0　任务 0")
        self.header_summary.setObjectName("summaryBadge")
        header.addWidget(self.header_summary)
        layout.addLayout(header)

        network_card = QFrame()
        network_card.setObjectName("card")
        network_card_layout = QVBoxLayout(network_card)
        network_card_layout.setContentsMargins(16, 12, 16, 14)
        network_card_layout.setSpacing(9)
        network_title = QLabel("网络与启动设置")
        network_title.setObjectName("sectionTitle")
        network_card_layout.addWidget(network_title)

        network = QHBoxLayout()
        self.nic = QComboBox()
        self.nic.currentIndexChanged.connect(self.select_nic)
        self.ip = QLineEdit(self.config["pxe_server_ip"])
        self.mask = QLineEdit(self.config["dhcp_subnet_mask"])
        self.pool_start = QLineEdit(self.config["dhcp_pool_start"])
        self.pool_end = QLineEdit(self.config["dhcp_pool_end"])
        self.gateway = QLineEdit(str(self.config.get("dhcp_gateway") or ""))
        dns_defaults = [
            value for value in re.split(
                r"[,，;；\s]+", str(self.config.get("dhcp_dns") or "").strip()
            ) if value
        ]
        self.dns1 = QLineEdit(dns_defaults[0] if dns_defaults else "")
        self.dns2 = QLineEdit(dns_defaults[1] if len(dns_defaults) > 1 else "")
        self.gateway.setPlaceholderText("可留空")
        self.dns1.setPlaceholderText("可留空")
        self.dns2.setPlaceholderText("可留空")
        self.local_timeout = QLineEdit(str(self.config.get("local_boot_timeout", 10)))
        network.addWidget(QLabel("部署网卡"))
        network.addWidget(self.nic, 2)
        network.addWidget(QLabel("服务器IP"))
        network.addWidget(self.ip)
        network.addWidget(QLabel("子网掩码"))
        network.addWidget(self.mask)
        network.addStretch()
        network_card_layout.addLayout(network)

        network_options = QHBoxLayout()
        network_options.addWidget(QLabel("地址池"))
        network_options.addWidget(self.pool_start)
        network_options.addWidget(QLabel("—"))
        network_options.addWidget(self.pool_end)
        network_options.addWidget(QLabel("网关"))
        network_options.addWidget(self.gateway)
        network_options.addWidget(QLabel("DNS1"))
        network_options.addWidget(self.dns1)
        network_options.addWidget(QLabel("DNS2"))
        network_options.addWidget(self.dns2)
        network_options.addWidget(QLabel("本地启动等待(秒)"))
        network_options.addWidget(self.local_timeout)
        network_options.addStretch()
        network_card_layout.addLayout(network_options)

        groups = QHBoxLayout()
        self.client_groups = QLineEdit("，".join(normalize_group_list(self.config.get("client_groups"))))
        self.save_groups_button = QPushButton("保存客户端分组")
        self.save_groups_button.clicked.connect(self.save_group_settings)
        self.preflight_button = QPushButton("部署环境自检")
        self.preflight_button.clicked.connect(self.show_preflight)
        groups.addWidget(QLabel("客户端分组（逗号分隔，第一项为默认组）"))
        groups.addWidget(self.client_groups, 1)
        groups.addWidget(self.save_groups_button)
        groups.addWidget(self.preflight_button)
        groups.addWidget(QLabel("列表筛选"))
        self.group_filter = QComboBox()
        self.group_filter.currentIndexChanged.connect(self.refresh_clients)
        groups.addWidget(self.group_filter)
        network_card_layout.addLayout(groups)
        layout.addWidget(network_card)

        client_card = QFrame()
        client_card.setObjectName("card")
        client_layout = QVBoxLayout(client_card)
        client_layout.setContentsMargins(16, 12, 16, 14)
        client_layout.setSpacing(8)
        client_tools = QHBoxLayout()
        client_title = QLabel("已注册客户端")
        client_title.setObjectName("sectionTitle")
        client_tools.addWidget(client_title)
        client_tools.addStretch()
        client_layout.addLayout(client_tools)
        client_actions = QHBoxLayout()
        self.registration_button = QPushButton("设置选中客户端任务（上传/下发）")
        self.registration_button.setObjectName("primaryButton")
        self.group_task_button = QPushButton("设置当前组任务")
        self.wake_selected_button = QPushButton("唤醒选中")
        self.wake_group_button = QPushButton("唤醒当前组")
        self.edit_clients_button = QPushButton("修改IP/计算机名")
        self.edit_clients_button.setObjectName("primaryButton")
        self.import_clients_button = QPushButton("导入客户端")
        self.export_clients_button = QPushButton("导出客户端")
        self.select_all_clients_button = QPushButton("全选")
        self.delete_clients_button = QPushButton("删除选中")
        self.delete_clients_button.setObjectName("dangerButton")
        self.registration_button.clicked.connect(self.register_client_task)
        self.group_task_button.clicked.connect(self.set_group_task)
        self.wake_selected_button.clicked.connect(self.wake_selected_clients)
        self.wake_group_button.clicked.connect(self.wake_current_group)
        self.edit_clients_button.clicked.connect(self.edit_selected_clients)
        self.import_clients_button.clicked.connect(self.import_clients)
        self.export_clients_button.clicked.connect(self.export_clients)
        self.select_all_clients_button.clicked.connect(self.client_table_select_all)
        self.delete_clients_button.clicked.connect(self.delete_selected_clients)
        for button in (
            self.registration_button, self.group_task_button, self.wake_selected_button,
            self.wake_group_button, self.edit_clients_button, self.import_clients_button,
            self.export_clients_button, self.select_all_clients_button,
            self.delete_clients_button,
        ):
            client_actions.addWidget(button)
        client_actions.addStretch()
        client_layout.addLayout(client_actions)
        self.client_table = QTableWidget(0, 13)
        self.client_table.setObjectName("dataTable")
        self.client_table.setHorizontalHeaderLabels(
            ["状态", "客户端名称", "注册IP", "MAC", "组", "架构", "CPU", "核心", "内存", "硬盘容量", "硬盘数", "候选系统盘", "注册时间"]
        )
        self.client_table.horizontalHeader().setStretchLastSection(True)
        self.client_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.client_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.client_table.setAlternatingRowColors(True)
        self.client_table.verticalHeader().setVisible(False)
        client_header = self.client_table.horizontalHeader()
        client_header.setSectionResizeMode(QHeaderView.ResizeToContents)
        client_header.setSectionsClickable(True)
        client_header.setSortIndicatorShown(True)
        self.client_table.setSortingEnabled(True)
        self.client_table.sortItems(8, Qt.DescendingOrder)
        self.client_table.cellDoubleClicked.connect(lambda _row, _column: self.register_client_task())
        client_layout.addWidget(self.client_table)
        layout.addWidget(client_card, 4)

        task_card = QFrame()
        task_card.setObjectName("card")
        task_layout = QVBoxLayout(task_card)
        task_layout.setContentsMargins(16, 12, 16, 14)
        task_layout.setSpacing(8)
        task_tools = QHBoxLayout()
        task_title = QLabel("镜像任务")
        task_title.setObjectName("sectionTitle")
        task_tools.addWidget(task_title)
        self.image_library_button = QPushButton("镜像库")
        self.image_library_button.clicked.connect(self.show_image_catalog)
        task_tools.addWidget(self.image_library_button)
        task_tools.addStretch()
        self.cancel_button = QPushButton("取消选中任务")
        self.select_all_tasks_button = QPushButton("全选")
        self.delete_tasks_button = QPushButton("删除任务")
        self.delete_tasks_button.setObjectName("dangerButton")
        self.clear_tasks_button = QPushButton("清空任务")
        self.clear_tasks_button.setObjectName("dangerButton")
        self.cancel_button.clicked.connect(self.cancel_task)
        self.select_all_tasks_button.clicked.connect(self.task_table_select_all)
        self.delete_tasks_button.clicked.connect(self.delete_selected_tasks)
        self.clear_tasks_button.clicked.connect(self.clear_all_tasks)
        task_tools.addWidget(self.cancel_button)
        task_tools.addWidget(self.select_all_tasks_button)
        task_tools.addWidget(self.delete_tasks_button)
        task_tools.addWidget(self.clear_tasks_button)
        task_layout.addLayout(task_tools)
        self.table = QTableWidget(0, 17)
        self.table.setObjectName("dataTable")
        self.table.setHorizontalHeaderLabels(
            [
                "ID", "类型", "方式", "镜像", "设备", "完成后", "状态",
                "客户端", "注册IP", "分组", "进度", "已写入", "开始时间",
                "耗时", "个性化", "信息", "创建时间",
            ]
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        task_layout.addWidget(self.table)
        layout.addWidget(task_card, 4)

        log_card = QFrame()
        log_card.setObjectName("card")
        log_layout = QVBoxLayout(log_card)
        log_layout.setContentsMargins(16, 10, 16, 12)
        log_layout.setSpacing(6)
        log_title = QLabel("PXE 服务日志 · 最新记录在最上方")
        log_title.setObjectName("sectionTitle")
        log_layout.addWidget(log_title)
        self.log = QTextEdit()
        self.log.setObjectName("serviceLog")
        self.log.setReadOnly(True)
        log_layout.addWidget(self.log)
        storage = QLabel(
            "任务：data/tasks.json　注册：data/registrations.json　终端：data/nodes.json　镜像：images/"
        )
        storage.setObjectName("storageHint")
        log_layout.addWidget(storage)
        layout.addWidget(log_card, 2)

        shell.addWidget(main, 1)
        self.setCentralWidget(root)
        self.setStyleSheet(MODERN_STYLE)
        self.refresh_group_filter()

    def show_image_catalog(self):
        self.image_catalog = rebuild_image_catalog()
        ImageCatalogDialog(self.image_catalog, self).exec_()

    def show_preflight(self):
        self.image_catalog = rebuild_image_catalog()
        PreflightDialog(self.config, self.pxe, self.image_catalog, self).exec_()

    def refresh_nics(self):
        selected = self.config.get("pxe_interface_name", "")
        self.nic.blockSignals(True)
        self.nic.clear()
        matched = 0
        found_selected = False
        for index, item in enumerate(self.pxe.interfaces()):
            self.nic.addItem(f"{item['name']} — {item['ip']} / {item['mask']}", item)
            if item["name"] == selected and item["ip"] == self.config.get("pxe_server_ip"):
                matched = index
                found_selected = True
        self.nic.setCurrentIndex(matched)
        self.nic.blockSignals(False)
        if self.nic.count():
            self.select_nic(update_defaults=not found_selected)

    def select_nic(self, _index=0, update_defaults=True):
        item = self.nic.currentData() or {}
        if not item.get("ip"):
            return
        self.ip.setText(item["ip"])
        self.mask.setText(item["mask"])
        if not update_defaults:
            return
        try:
            network = ipaddress.IPv4Network(f"{item['ip']}/{item['mask']}", strict=False)
            start = min(int(network.network_address) + 100, int(network.broadcast_address) - 1)
            end = min(int(network.network_address) + 200, int(network.broadcast_address) - 1)
            if start == int(ipaddress.IPv4Address(item["ip"])):
                start += 1
            self.pool_start.setText(str(ipaddress.IPv4Address(start)))
            self.pool_end.setText(str(ipaddress.IPv4Address(max(start, end))))
            gateway_parts = str(item["ip"]).split(".")
            gateway_parts[-1] = "254"
            gateway = ipaddress.IPv4Address(".".join(gateway_parts))
            if gateway not in network or gateway in {
                network.network_address, network.broadcast_address,
            }:
                gateway = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
            self.gateway.setText(str(gateway))
        except ValueError:
            pass

    def available_groups(self) -> list[str]:
        groups = normalize_group_list(self.config.get("client_groups"))
        for registration in self.store.registrations():
            group = normalize_group_name(str(registration.get("group") or "默认组"))
            if group not in groups:
                groups.append(group)
        return groups

    def refresh_group_filter(self):
        selected = str(self.group_filter.currentData() or "")
        groups = self.available_groups()
        self.group_filter.blockSignals(True)
        self.group_filter.clear()
        self.group_filter.addItem("全部分组", "")
        for group in groups:
            self.group_filter.addItem(group, group)
        index = self.group_filter.findData(selected)
        self.group_filter.setCurrentIndex(index if index >= 0 else 0)
        self.group_filter.blockSignals(False)

    def current_group(self) -> str:
        return str(self.group_filter.currentData() or "")

    def group_payload(self) -> dict:
        groups = self.available_groups()
        return {"default_group": groups[0], "groups": groups}

    def save_group_settings(self):
        groups = normalize_group_list(self.client_groups.text())
        self.config["client_groups"] = groups
        self.client_groups.setText("，".join(groups))
        atomic_json(CONFIG_FILE, self.config)
        self.refresh_group_filter()
        self.refresh_clients()
        QMessageBox.information(
            self, "分组已保存",
            f"默认组：{groups[0]}\n客户端注册时输入 ? 可查询并选择这些分组。",
        )

    def save_network(self):
        item = self.nic.currentData() or {}
        values = {
            "pxe_interface_name": item.get("name", ""),
            "pxe_server_ip": self.ip.text().strip(),
            "dhcp_mode": "server",
            "uefi_ipxe_driver": "snp",
            "dhcp_subnet_mask": self.mask.text().strip(),
            "dhcp_pool_start": self.pool_start.text().strip(),
            "dhcp_pool_end": self.pool_end.text().strip(),
            "dhcp_gateway": self.gateway.text().strip(),
            "dhcp_dns": ",".join(
                value for value in (
                    self.dns1.text().strip(), self.dns2.text().strip()
                ) if value
            ),
            "dhcp_lease_seconds": 28800,
        }
        self.pxe.apply_network_config(values)
        self.config.update(self.pxe.config)
        try:
            timeout = int(self.local_timeout.text().strip())
        except ValueError as exc:
            raise ValueError("本地启动等待秒数必须是整数") from exc
        self.config["local_boot_timeout"] = max(1, min(300, timeout))
        self.local_timeout.setText(str(self.config["local_boot_timeout"]))
        atomic_json(CONFIG_FILE, self.config)

    def write_boot_menu(self):
        server = self.config["pxe_server_ip"]
        port = int(self.config["tcp_port"])
        token = self.config["agent_token"]
        timeout_ms = int(self.config.get("local_boot_timeout", 10)) * 1000
        script = f"""#!ipxe
{ipxe_architecture_setup()}
chain tftp://{server}/clients/${{net0/mac:hexhyp}}.ipxe || goto menu
goto menu

:menu
menu Jingyun ZOS Deploy
item --key r register Register this computer
item --key l local Boot from local disk
item --key s shell Open iPXE command shell
choose --default local --timeout {timeout_ms} target || goto local
goto ${{target}}

:register
kernel tftp://{server}/${{zos_arch}}/zos/${{zos_kernel}} ${{zos_args}} ${{zos_netargs}} jy_mode=register jy_server={server} jy_port={port} jy_token={token} mac=${{net0/mac}}
initrd --name ${{zos_init}} tftp://{server}/${{zos_arch}}/zos/${{zos_init}}
boot || goto failed

:local
iseq ${{platform}} efi && sanboot --no-describe --drive 0 || sanboot --no-describe --drive 0x80
exit

:shell
shell
goto menu

:failed
echo Boot failed
sleep 3
goto menu
"""
        Path(self.config["tftp_root"], "boot.ipxe").write_text(script, encoding="ascii")
        self.sync_client_boot_scripts()

    def sync_client_boot_scripts(self):
        root = Path(self.config["tftp_root"], "clients")
        root.mkdir(parents=True, exist_ok=True)
        active: dict[str, dict] = {}
        for task in self.store.tasks():
            mac = str(task.get("target_mac") or "")
            if task.get("status") == "queued" and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                active[mac] = task
        expected = {mac.replace(":", "-") + ".ipxe" for mac in active}
        for path in root.glob("*.ipxe"):
            if path.name not in expected:
                try:
                    path.unlink()
                except OSError:
                    pass
        server = self.config["pxe_server_ip"]
        port = int(self.config["tcp_port"])
        token = self.config["agent_token"]
        for mac, task in active.items():
            mode = "deploy" if task.get("action") == "deploy" else "capture"
            script = f"""#!ipxe
{ipxe_architecture_setup()}
echo Automatic {mode} task {task.get('id', '')} for {mac}
kernel tftp://{server}/${{zos_arch}}/zos/${{zos_kernel}} ${{zos_args}} ${{zos_netargs}} jy_mode={mode} jy_auto=1 jy_server={server} jy_port={port} jy_token={token} mac=${{net0/mac}}
initrd --name ${{zos_init}} tftp://{server}/${{zos_arch}}/zos/${{zos_init}}
boot
"""
            target = root / f"{mac.replace(':', '-')}.ipxe"
            if not target.exists() or target.read_text(encoding="ascii") != script:
                target.write_text(script, encoding="ascii")

    def start_services(self):
        try:
            self.save_network()
            self.write_boot_menu()
            self.upload_server = UploadServer(
                ("0.0.0.0", int(self.config["tcp_port"])), self.store,
                self.config["agent_token"], self.group_payload, self.multicast,
            )
            self.upload_thread = threading.Thread(target=self.upload_server.serve_forever, daemon=True)
            self.upload_thread.start()
            self.pxe.start()
            self.status.setText(
                f"运行中：DHCP/TFTP + TCP单独传输 + ZOS可靠组播　"
                f"服务器 {self.config['pxe_server_ip']}:{self.config['tcp_port']}"
            )
        except Exception as exc:
            self.stop_services()
            QMessageBox.warning(self, "启动失败", str(exc))

    def stop_services(self):
        self.multicast.stop_all()
        self.pxe.stop()
        if self.upload_server:
            self.upload_server.shutdown()
            self.upload_server.server_close()
        self.upload_server = None
        self.status.setText("服务未启动")

    def identity_settings(
        self, name: str, ip: str, mac: str,
        apply_name: bool, apply_ip: bool,
    ) -> dict:
        address = ""
        prefix = 24
        gateway = ""
        dns_values: list[str] = []
        if apply_ip:
            if not ip:
                raise ValueError(f"客户端 {name} 没有已注册IP，不能设置固定IP")
            address = str(ipaddress.IPv4Address(ip))
            prefix = ipaddress.IPv4Network(
                f"0.0.0.0/{self.mask.text().strip()}", strict=False
            ).prefixlen
            gateway = self.gateway.text().strip()
            dns_values = [
                value for value in (
                    self.dns1.text().strip(), self.dns2.text().strip()
                ) if value
            ]
        return {
            "enabled": bool(apply_name or apply_ip),
            "apply_name": bool(apply_name),
            "apply_ip": bool(apply_ip),
            "network_mode": "static" if apply_ip else "dhcp",
            "name": safe_computer_name(name, mac) if apply_name else "",
            "ip": address,
            "prefix": prefix,
            "gateway": gateway,
            "dns": dns_values,
        }

    def register_client_task(self):
        selected_mac = self.selected_client_mac()
        if not selected_mac:
            QMessageBox.information(
                self, "请先选择客户端",
                "请先在“已注册客户端”列表中选择一台客户端，再设置上传或部署任务。\n"
                "新客户端请先从PXE菜单选择“Register this computer”。",
            )
            return
        dialog = RegistrationDialog(self.store, self.available_groups(), selected_mac, self)
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            mac = normalize_mac(dialog.mac.text())
            name = dialog.name.text().strip() or "未命名客户端"
            group = normalize_group_name(str(dialog.group.currentData() or "默认组"))
            device = dialog.device.text().strip() or "auto"
            if device != "auto" and (
                not re.fullmatch(r"/dev/[A-Za-z0-9._/+:-]+", device) or ".." in device
            ):
                raise ValueError("源盘/目标盘请使用 auto，或填写类似 /dev/sda 的设备")
            self.store.save_registration(mac, name, group)
            self.store.cancel_pending_for_mac(mac)
            action = str(dialog.action.currentData())
            task = None
            if action == "capture":
                image_name = dialog.template.text().strip() or "{hostname}-{date}"
                image_name = image_name.replace("{hostname}", name)
                image_name = image_name.replace("{mac}", mac.replace(":", "-"))
                image_name = image_name.replace("{date}", time.strftime("%Y%m%d-%H%M%S"))
                task = self.store.create_task(
                    image_name, device, "raw_disk", "auto", target_mac=mac,
                    post_action=str(dialog.post_action.currentData()), target_group=group,
                )
            elif action == "deploy":
                if dialog.image.count() == 0:
                    raise ValueError("images目录中没有可下发镜像")
                image_file = str(dialog.image.currentData())
                identity = None
                apply_name = dialog.apply_name.isChecked()
                apply_ip = dialog.apply_ip.isChecked()
                if apply_name or apply_ip:
                    known = dialog.client_rows.get(mac, {})
                    registered_ip = str(known.get("ip") or "")
                    identity = self.identity_settings(
                        name, registered_ip, mac, apply_name, apply_ip
                    )
                identity_text = (
                    f"计算机名：{identity['name'] if apply_name else '保留镜像原名称'}\n"
                    f"IPv4：{identity['ip'] + '/' + str(identity['prefix']) if apply_ip else '保持DHCP自动获取'}\n"
                    f"网关：{identity['gateway'] or '空'}\n"
                    f"DNS：{', '.join(identity['dns']) or '空'}\n"
                    if identity else
                    "计算机名：保留镜像原名称\nIPv4：保持DHCP自动获取\n"
                )
                image_path = (IMAGE_DIR / Path(image_file).name).resolve()
                image_meta = read_json(image_path.with_suffix(image_path.suffix + ".json"), {})
                image_arch = normalize_architecture(str(image_meta.get("source_arch") or ""))
                known_registration = next(
                    (item for item in self.store.registrations() if item.get("mac") == mac), {}
                )
                hw = client_hardware_info(known_registration)
                mismatch = architecture_warning(image_arch, known_registration)
                hardware_text = (
                    f"硬件：{hw['arch']} / {hw['cpu_model']}"
                    + (f" / {hw['cpu_cores']}核" if hw['cpu_cores'] else "")
                    + f" / 内存 {format_bytes_gib(hw['memory_bytes'])}"
                    + f" / 最大硬盘 {format_bytes_gib(hw['largest_disk_bytes'])}\n"
                )
                compatibility_text = (
                    f"\n⚠ {mismatch}\n这只是兼容性提示，仍可选择继续下发。\n"
                    if mismatch else "\n兼容性：CPU架构未发现不匹配。\n"
                )
                answer = QMessageBox.warning(
                    self,
                    "确认自动下发",
                    f"客户端：{name} ({mac})\n镜像：{image_file}\n镜像架构：{image_arch}\n目标盘：{device}\n"
                    + hardware_text + identity_text + compatibility_text
                    + "\n"
                    "该客户端下次PXE开机将自动覆盖目标硬盘，是否继续下发？",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                if answer != QMessageBox.Yes:
                    return
                task = self.store.create_deploy_task(
                    image_file, device, target_mac=mac,
                    post_action=str(dialog.post_action.currentData()), target_group=group,
                    identity=identity,
                )
            self.sync_client_boot_scripts()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "客户端任务设置失败", str(exc))
            return
        if task:
            self.pxe.log(
                f"客户端任务设置成功：{name} ({mac})，任务 {task['id']}，"
                "下次PXE开机自动执行一次"
            )
        else:
            self.pxe.log(
                f"客户端启动策略设置成功：{name} ({mac})，无待执行任务，"
                "PXE启动时倒计时进入本地系统"
            )
        # 关闭设置窗口后任务会立即出现在列表中；不再弹出第二个“设置完成”窗口。
        self.refresh_view()

    def set_group_task(self):
        group = self.current_group()
        if not group:
            QMessageBox.information(self, "请选择分组", "请先在“列表筛选”中选择一个具体分组。")
            return
        clients = [row for row in self.registered_client_rows() if row["group"] == group]
        if not clients:
            QMessageBox.information(self, "分组为空", f"分组“{group}”中没有已注册客户端。")
            return
        dialog = GroupTaskDialog(group, len(clients), self)
        if dialog.exec_() != QDialog.Accepted:
            return
        action = str(dialog.action.currentData())
        transfer_mode = str(dialog.transfer_mode.currentData() or "unicast")
        multicast_profile = str(dialog.multicast_profile.currentData() or "gigabit")
        apply_name = action == "deploy" and dialog.apply_name.isChecked()
        apply_ip = action == "deploy" and dialog.apply_ip.isChecked()
        apply_identity = apply_name or apply_ip
        device = dialog.device.text().strip() or "auto"
        post_action = str(dialog.post_action.currentData())
        if device != "auto" and (
            not re.fullmatch(r"/dev/[A-Za-z0-9._/+:-]+", device) or ".." in device
        ):
            QMessageBox.warning(self, "设备无效", "源盘/目标盘请使用 auto，或填写类似 /dev/sda 的设备。")
            return
        image_file = str(dialog.image.currentData() or "")
        if action == "deploy" and not image_file:
            QMessageBox.warning(self, "没有镜像", "images目录中没有可下发的RAW整盘镜像。")
            return
        if action == "deploy" and transfer_mode == "multicast" and len(clients) < 2:
            QMessageBox.warning(
                self, "组播至少需要2台客户端",
                "当前分组只有1台客户端，请选择“单独下发”。",
            )
            return
        if action == "deploy" and transfer_mode == "multicast":
            client_arches = {
                normalize_architecture(str(client.get("arch") or ""))
                for client in clients
            }
            client_arches.discard("unknown")
            # ARM64/LoongArch64 use the built-in ZOSMC reliable multicast path.
            # x86_64 keeps upstream UDPcast compatibility for now.
            needs_udpcast = client_arches not in ({"arm64"}, {"loongarch64"})
            if needs_udpcast:
                try:
                    self.multicast.sender_path()
                except ValueError:
                    machine = platform.machine()
                    bundled = ROOT / "tools" / "udpcast" / (
                        "linux-aarch64" if machine.lower() in {"aarch64", "arm64"}
                        else "linux-x86_64" if machine.lower() in {"amd64", "x86_64"}
                        else "linux-loongarch64"
                    ) / "udp-sender"
                    QMessageBox.warning(
                        self, "缺少离线组播组件",
                        f"当前管理端为 {platform.system()}/{machine}，未找到可用的 udp-sender。\n\n"
                        "部署网络允许完全离线运行，本程序不会再尝试 apt/yum 在线安装。\n"
                        f"请把对应架构的 udp-sender 放到：\n{bundled}\n"
                        "并赋予执行权限后重新选择组播。",
                    )
                    return
        group_image_arch = "unknown"
        group_mismatches: list[dict] = []
        if action == "deploy":
            try:
                preview_image = (IMAGE_DIR / Path(image_file).name).resolve()
                preview_image.relative_to(IMAGE_DIR.resolve())
                preview_meta = read_json(preview_image.with_suffix(preview_image.suffix + ".json"), {})
                group_image_arch = normalize_architecture(str(preview_meta.get("source_arch") or ""))
                group_mismatches = [
                    client for client in clients
                    if group_image_arch != "unknown"
                    and normalize_architecture(str(client.get("arch") or "")) != "unknown"
                    and normalize_architecture(str(client.get("arch") or "")) != group_image_arch
                ]
            except (OSError, ValueError):
                pass
        warning = (
            f"分组：{group}\n客户端数量：{len(clients)}\n"
            f"任务：{'分别上传模板' if action == 'capture' else '部署同一镜像'}\n\n"
        )
        if action == "deploy":
            warning += (
                f"镜像：{image_file}\n镜像架构：{group_image_arch}\n目标盘：{device}\n"
                f"下发方式：{transfer_mode_text(transfer_mode)}\n"
                + (
                    f"组播速度：{multicast_profile_text(multicast_profile)}\n"
                    if transfer_mode == "multicast" else ""
                )
                + (
                    (
                        f"计算机名：{'按注册名称修改' if apply_name else '保留镜像原名称'}\n"
                        f"IPv4：{'按注册IP设置固定地址' if apply_ip else '保持DHCP自动获取'}\n"
                        f"网关：{self.gateway.text().strip() or '空'}\n"
                        f"DNS：{', '.join(value for value in (self.dns1.text().strip(), self.dns2.text().strip()) if value) or '空'}\n"
                    )
                )
                + (
                    (
                        "\n⚠ CPU架构不匹配客户端：" + str(len(group_mismatches)) + " 台\n"
                        + "\n".join(
                            f"  {item.get('name') or item.get('mac')}：{item.get('arch') or 'unknown'}"
                            for item in group_mismatches[:12]
                        )
                        + (f"\n  ……另有 {len(group_mismatches)-12} 台" if len(group_mismatches) > 12 else "")
                        + "\n这只是兼容性提示，可继续为整个分组建立任务。\n"
                    )
                    if group_mismatches else "\n兼容性：组内已识别客户端CPU架构未发现不匹配。\n"
                )
                +
                "将覆盖组内客户端目标硬盘上的全部分区和数据，无法撤销。\n\n"
            )
            if transfer_mode == "multicast":
                warning += (
                    "组播会等待本次任务中的全部客户端上线并完成目标盘检查；"
                    "少一台都不会开始写盘。\n\n"
                )
        warning += "确认为组内每台客户端建立MAC定向任务吗？"
        answer = QMessageBox.warning(
            self, "确认分组任务", warning,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        created = []
        try:
            if action == "deploy":
                image_path = (IMAGE_DIR / Path(image_file).name).resolve()
                image_path.relative_to(IMAGE_DIR.resolve())
                metadata = read_json(image_path.with_suffix(image_path.suffix + ".json"), {})
                if not image_path.is_file() or metadata.get("image_type") != "raw_disk":
                    raise ValueError("所选镜像不是有效的RAW整盘镜像")
                if int(metadata.get("source_bytes") or 0) <= 0:
                    raise ValueError("所选镜像缺少源硬盘容量信息")
                if apply_ip:
                    identities = [
                        self.identity_settings(
                            str(client["name"]), str(client["ip"]), str(client["mac"]),
                            apply_name, apply_ip,
                        )
                        for client in clients
                    ]
                    addresses = [item["ip"] for item in identities]
                    if len(addresses) != len(set(addresses)):
                        raise ValueError("组内存在重复注册IP，不能启用自动IP配置")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            multicast_session_id = (
                uuid.uuid4().hex[:12]
                if action == "deploy" and transfer_mode == "multicast"
                else ""
            )
            used_names: set[str] = set()
            for client in clients:
                mac = normalize_mac(client["mac"])
                self.store.cancel_pending_for_mac(mac)
                if action == "capture":
                    template = dialog.template.text().strip() or "{group}-{hostname}-{date}"
                    image_name = template.replace("{group}", group)
                    image_name = image_name.replace("{hostname}", str(client["name"]))
                    image_name = image_name.replace("{mac}", mac.replace(":", "-"))
                    image_name = image_name.replace("{date}", stamp)
                    image_name = safe_name(image_name)
                    if image_name in used_names:
                        image_name = safe_name(f"{image_name}-{mac.replace(':', '')[-6:]}")
                    used_names.add(image_name)
                    created.append(self.store.create_task(
                        image_name, device, "raw_disk", "auto", target_mac=mac,
                        post_action=post_action, target_group=group,
                    ))
                else:
                    identity = (
                        self.identity_settings(
                            str(client["name"]), str(client["ip"]), mac,
                            apply_name, apply_ip,
                        )
                        if apply_identity else None
                    )
                    created.append(self.store.create_deploy_task(
                        image_file, device, target_mac=mac, post_action=post_action,
                        target_group=group, transfer_mode=transfer_mode,
                        multicast_session_id=multicast_session_id,
                        multicast_expected=len(clients) if multicast_session_id else 0,
                        multicast_profile=multicast_profile,
                        identity=identity,
                    ))
            self.sync_client_boot_scripts()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "分组任务建立失败", str(exc))
            return
        self.refresh_view()
        QMessageBox.information(
            self, "分组任务已建立",
            f"已为分组“{group}”建立 {len(created)} 个MAC定向任务。\n"
            f"下发方式：{transfer_mode_text(transfer_mode) if action == 'deploy' else '分别上传'}\n"
            + (
                f"组播速度：{multicast_profile_text(multicast_profile)}\n"
                if action == "deploy" and transfer_mode == "multicast" else ""
            )
            + (
                (
                    f"计算机名：{'按注册名称修改' if apply_name else '保留镜像原名称'}\n"
                    f"IPv4：{'按注册IP固定' if apply_ip else '保持DHCP自动获取'}\n"
                )
                if apply_identity else
                "计算机名：保留镜像原名称\nIPv4：保持DHCP自动获取\n"
            )
            + (
                "全部客户端完成上线和磁盘检查后才会统一开始组播写盘。"
                if action == "deploy" and transfer_mode == "multicast"
                else "客户端下次PXE启动时会按MAC自动领取各自任务。"
            ),
        )

    def send_wol(self, macs: list[str], label: str):
        unique_macs = []
        for value in macs:
            try:
                mac = normalize_mac(value)
            except ValueError:
                continue
            if mac not in unique_macs:
                unique_macs.append(mac)
        if not unique_macs:
            QMessageBox.information(self, "没有客户端", "没有找到可唤醒的有效MAC地址。")
            return
        try:
            source_ip = ipaddress.IPv4Address(self.ip.text().strip())
            network = ipaddress.IPv4Network(
                f"{source_ip}/{self.mask.text().strip()}", strict=False
            )
            broadcast = str(network.broadcast_address)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind((str(source_ip), 0))
            except OSError:
                pass
            sent = 0
            try:
                for mac in unique_macs:
                    packet = build_wol_packet(mac)
                    for _repeat in range(3):
                        for port in (7, 9):
                            sock.sendto(packet, (broadcast, port))
                    sent += 1
            finally:
                sock.close()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "唤醒失败", str(exc))
            return
        self.pxe.log(f"WOL批量唤醒：{label}，已向 {broadcast} 发送 {sent} 台客户端")
        QMessageBox.information(
            self, "唤醒命令已发送",
            f"目标：{label}\n客户端：{sent}台\n广播地址：{broadcast}\n\n"
            "客户端必须开启BIOS和网卡的网络唤醒功能。",
        )

    def wake_selected_clients(self):
        macs = self.selected_client_macs()
        if not macs:
            QMessageBox.information(self, "请先选择客户端", "可按 Ctrl/Shift 选择多台客户端。")
            return
        self.send_wol(macs, "选中客户端")

    def wake_current_group(self):
        group = self.current_group()
        if not group:
            QMessageBox.information(self, "请选择分组", "请先在“列表筛选”中选择一个具体分组。")
            return
        macs = [
            row["mac"] for row in self.registered_client_rows()
            if row["group"] == group
        ]
        self.send_wol(macs, f"分组 {group}")

    def export_clients(self):
        rows = self.filtered_client_rows()
        if not rows:
            QMessageBox.information(self, "没有数据", "当前列表中没有可导出的客户端。")
            return
        group = self.current_group() or "全部分组"
        default_name = f"ZOS客户端列表-{safe_name(group)}-{time.strftime('%Y%m%d-%H%M%S')}.xlsx"
        filename, selected_filter = QFileDialog.getSaveFileName(
            self, "导出客户端列表", str(ROOT / default_name),
            "Excel 工作簿 (*.xlsx);;文本文件 (*.txt)",
        )
        if not filename:
            return
        path = Path(filename)
        if not path.suffix:
            path = path.with_suffix(".txt" if "文本" in selected_filter else ".xlsx")
        headers = ["状态", "客户端名称", "注册IP", "MAC", "组", "硬盘数", "候选系统盘", "系统判断", "注册时间"]
        values = [
            [
                row["status"], row["name"], row["ip"], row["mac"], row["group"],
                str(row["disk_count"]), row["selected_disk"], row["system_hint"],
                row["registered_at"],
            ]
            for row in rows
        ]
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix.lower() == ".txt":
                lines = ["\t".join(headers), *("\t".join(row) for row in values)]
                path.write_text("\n".join(lines) + "\n", encoding="utf-8-sig")
            else:
                if path.suffix.lower() != ".xlsx":
                    path = path.with_suffix(".xlsx")
                write_xlsx(path, headers, values)
        except OSError as exc:
            QMessageBox.warning(self, "导出失败", str(exc))
            return
        QMessageBox.information(
            self, "导出完成", f"已导出 {len(values)} 台客户端：\n{path}"
        )

    def import_clients(self):
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self, "导入客户端列表", str(ROOT),
            "客户端列表 (*.xlsx *.txt *.csv);;Excel 工作簿 (*.xlsx);;文本文件 (*.txt *.csv)",
        )
        if not filename:
            return
        try:
            imported, errors = parse_client_import(Path(filename))
            created, updated = self.store.import_registrations(imported)
            groups = normalize_group_list(self.config.get("client_groups"))
            for row in imported:
                group = normalize_group_name(str(row.get("group") or "默认组"))
                if group not in groups:
                    groups.append(group)
            self.config["client_groups"] = groups
            self.client_groups.setText("，".join(groups))
            atomic_json(CONFIG_FILE, self.config)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            QMessageBox.warning(self, "导入失败", str(exc))
            return
        self.refresh_group_filter()
        self.refresh_clients()
        self.pxe.log(
            f"导入客户端列表：新增 {created} 台，更新 {updated} 台，跳过 {len(errors)} 行"
        )
        detail = ""
        if errors:
            detail = "\n\n以下记录已跳过：\n" + "\n".join(errors[:8])
            if len(errors) > 8:
                detail += f"\n……另有 {len(errors) - 8} 行"
        QMessageBox.information(
            self, "导入完成",
            f"新增客户端：{created} 台\n更新客户端：{updated} 台\n跳过无效记录：{len(errors)} 行{detail}",
        )

    def client_table_select_all(self):
        self.client_table.selectAll()

    def task_table_select_all(self):
        self.table.selectAll()

    def selected_task_ids(self) -> list[str]:
        selection = self.table.selectionModel()
        if selection is None:
            return []
        task_ids: list[str] = []
        for index in selection.selectedRows():
            item = self.table.item(index.row(), 0)
            if item and item.text() and item.text() not in task_ids:
                task_ids.append(item.text())
        return task_ids

    def delete_selected_clients(self):
        macs = self.selected_client_macs()
        if not macs:
            QMessageBox.information(self, "请选择客户端", "可按 Ctrl/Shift 多选，或点击“全选”。")
            return
        answer = QMessageBox.warning(
            self, "确认删除客户端",
            f"将删除选中的 {len(macs)} 台客户端注册记录及终端缓存。\n"
            "这些客户端对应的待执行任务会自动取消，已经完成的任务历史和镜像文件不会删除。\n\n"
            "确认继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        try:
            deleted = self.store.delete_registrations(macs)
        except ValueError as exc:
            QMessageBox.warning(self, "不能删除", str(exc))
            return
        self.refresh_group_filter()
        self.refresh_view()
        self.pxe.log(f"批量删除客户端：{deleted} 台")
        QMessageBox.information(self, "删除完成", f"已删除 {deleted} 台客户端。")

    def delete_selected_tasks(self):
        task_ids = self.selected_task_ids()
        if not task_ids:
            QMessageBox.information(self, "请选择任务", "可按 Ctrl/Shift 多选，或点击“全选”。")
            return
        answer = QMessageBox.warning(
            self, "确认删除任务",
            f"将删除选中的 {len(task_ids)} 条任务记录。\n"
            "组播任务将按完整会话一起删除；镜像文件不会随任务记录删除。\n\n确认继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        force = False
        try:
            deleted, sessions = self.store.delete_tasks(task_ids)
        except ValueError as exc:
            if "正在执行" not in str(exc) and "已经领取" not in str(exc):
                QMessageBox.warning(self, "不能删除", str(exc))
                return
            force_answer = QMessageBox.warning(
                self, "任务仍标记为执行中",
                str(exc) + "\n\n客户端可能已经关机、死机或网络中断。\n"
                "是否强制删除这些任务？\n\n"
                "强制删除只清理任务和发送会话，不会删除镜像文件。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if force_answer != QMessageBox.Yes:
                return
            force = True
            deleted, sessions = self.store.delete_tasks(task_ids, force=True)
        for session_id in sessions:
            self.multicast.stop_session(session_id)
        self.refresh_view()
        self.pxe.log(f"批量删除任务：{deleted} 条")
        QMessageBox.information(self, "删除完成", f"已删除 {deleted} 条任务记录。")

    def clear_all_tasks(self):
        rows = self.store.tasks()
        if not rows:
            QMessageBox.information(self, "暂无任务", "镜像任务列表已经为空。")
            return
        answer = QMessageBox.warning(
            self, "确认清空任务",
            f"将清空当前全部 {len(rows)} 条任务记录。\n"
            "如有执行中/已领取任务，可在下一步选择强制清空；镜像文件不会删除。\n\n"
            "确认继续吗？",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        all_ids = [str(row.get("id") or "") for row in rows]
        try:
            deleted, sessions = self.store.delete_tasks(all_ids)
        except ValueError as exc:
            force_answer = QMessageBox.warning(
                self, "存在执行中任务",
                str(exc) + "\n\n部分客户端可能已经关机、死机或网络中断。\n"
                "是否强制清空全部任务？\n\n"
                "只清理任务记录和组播发送会话，不会删除镜像文件。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if force_answer != QMessageBox.Yes:
                return
            deleted, sessions = self.store.delete_tasks(all_ids, force=True)
        for session_id in sessions:
            self.multicast.stop_session(session_id)
        self.refresh_view()
        self.pxe.log(f"清空镜像任务：{deleted} 条")
        QMessageBox.information(self, "清空完成", f"已清空 {deleted} 条任务记录。")

    def selected_client_mac(self) -> str:
        row = self.client_table.currentRow()
        if row < 0:
            return ""
        item = self.client_table.item(row, 3)
        return item.text().strip().lower() if item else ""

    def selected_client_macs(self) -> list[str]:
        selection = self.client_table.selectionModel()
        if selection is None:
            return []
        macs = []
        for index in selection.selectedRows():
            item = self.client_table.item(index.row(), 3)
            if item:
                mac = item.text().strip().lower()
                if mac and mac not in macs:
                    macs.append(mac)
        return macs

    def selected_client_records(self) -> list[dict]:
        selection = self.client_table.selectionModel()
        if selection is None:
            return []
        rows_by_mac = {
            str(row.get("mac") or "").strip().lower(): row
            for row in self.filtered_client_rows()
        }
        selected: list[dict] = []
        for index in sorted(selection.selectedRows(), key=lambda item: item.row()):
            mac_item = self.client_table.item(index.row(), 3)
            mac = mac_item.text().strip().lower() if mac_item else ""
            row = rows_by_mac.get(mac)
            if row is not None:
                selected.append(dict(row))
        return selected

    def edit_selected_clients(self):
        clients = self.selected_client_records()
        if not clients:
            QMessageBox.information(
                self, "请选择客户端",
                "选择一台可直接修改；按 Ctrl/Shift 选择多台可按顺序批量修改。",
            )
            return
        dialog = ClientIdentityEditDialog(clients, self.mask.text().strip(), self)
        if dialog.exec_() != QDialog.Accepted:
            return
        try:
            updated = self.store.update_registration_identities(dialog.result_updates())
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "修改失败", str(exc))
            return
        self.refresh_view()
        mode = "单台" if updated == 1 else "批量"
        self.pxe.log(f"{mode}修改客户端IP/计算机名：{updated} 台")

    def registered_client_rows(self) -> list[dict]:
        registrations = self.store.registrations()
        nodes = {
            str(item.get("mac") or "").lower(): item
            for item in read_json(NODE_FILE, [])
            if item.get("mac")
        }
        rows = []
        now = time.time()
        for registration in registrations:
            mac = str(registration.get("mac") or "").lower()
            node = nodes.get(mac, {})
            analysis = node.get("disk_analysis") or registration.get("disk_analysis") or {}
            last_seen = max(
                str(registration.get("last_seen") or ""),
                str(node.get("last_seen") or ""),
            )
            online = False
            try:
                seen_at = time.mktime(time.strptime(last_seen, "%Y-%m-%d %H:%M:%S"))
                online = now - seen_at <= 300
            except ValueError:
                pass
            source = dict(registration)
            if node.get("inventory"):
                source["inventory"] = node.get("inventory")
            source["disk_analysis"] = analysis
            hardware = client_hardware_info(source)
            rows.append({
                "status": "在线" if online else "已注册",
                "name": registration.get("name") or node.get("hostname") or "未命名客户端",
                "ip": registration.get("ip") or node.get("configured_ip") or "",
                "reported_ip": node.get("ip") or registration.get("reported_ip") or "",
                "mac": mac,
                "group": registration.get("group") or node.get("group") or "默认组",
                "arch": hardware["arch"],
                "cpu_model": hardware["cpu_model"],
                "cpu_cores": hardware["cpu_cores"],
                "memory_text": format_bytes_gib(hardware["memory_bytes"]),
                "largest_disk_text": format_bytes_gib(hardware["largest_disk_bytes"]),
                "disk_count": int(analysis.get("count") or 0),
                "selected_disk": analysis.get("selected") or "",
                "system_hint": analysis.get("system_hint") or "",
                "registered_at": registration.get("registered_at") or "",
            })
        rows.sort(key=lambda item: item["registered_at"], reverse=True)
        return rows

    def filtered_client_rows(self) -> list[dict]:
        group = self.current_group()
        rows = self.registered_client_rows()
        return [row for row in rows if not group or row["group"] == group]

    def refresh_clients(self, _index=None):
        selected_macs = set(self.selected_client_macs())
        rows = self.filtered_client_rows()
        header = self.client_table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        sorting_enabled = self.client_table.isSortingEnabled()

        self.client_table.setSortingEnabled(False)
        self.client_table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            values = [
                row["status"], row["name"], row["ip"], row["mac"], row["group"],
                row["arch"], row["cpu_model"], row["cpu_cores"], row["memory_text"],
                row["largest_disk_text"], row["disk_count"], row["selected_disk"],
                row["registered_at"],
            ]
            for column, value in enumerate(values):
                item = SortableTableWidgetItem(
                    value, client_table_sort_key(column, value)
                )
                if column == 2 and row.get("reported_ip") and row.get("reported_ip") != row.get("ip"):
                    item.setToolTip(f"当前PXE通信IP：{row['reported_ip']}")
                self.client_table.setItem(index, column, item)

        self.client_table.setSortingEnabled(sorting_enabled)
        if sorting_enabled and sort_column >= 0:
            self.client_table.sortItems(sort_column, sort_order)

        for index in range(self.client_table.rowCount()):
            mac_item = self.client_table.item(index, 3)
            mac = mac_item.text().strip().lower() if mac_item else ""
            if mac in selected_macs:
                for column in range(self.client_table.columnCount()):
                    item = self.client_table.item(index, column)
                    if item:
                        item.setSelected(True)

    def cancel_task(self):
        row = self.table.currentRow()
        if row < 0:
            return
        task_id = self.table.item(row, 0).text()
        task = next((item for item in self.store.tasks() if item.get("id") == task_id), {})
        session_id = str(task.get("multicast_session_id") or "")
        if session_id:
            answer = QMessageBox.warning(
                self, "取消整组组播任务",
                "选中的任务属于组播会话。取消后，本次组播中的所有客户端任务都会一起取消，"
                "正在运行的发送器也会停止。确认继续吗？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return
        self.store.cancel(task_id)
        self.multicast.stop_session(session_id)
        self.refresh_view()

    def refresh_view(self):
        selected_task_ids = set(self.selected_task_ids())
        self.sync_client_boot_scripts()
        self.refresh_clients()
        registrations = {
            str(item.get("mac") or "").lower(): item
            for item in self.store.registrations() if item.get("mac")
        }
        rows = list(reversed(self.store.tasks()))
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            task_mac = str(row.get("target_mac") or row.get("mac") or "").lower()
            registered = registrations.get(task_mac, {})
            task_client_name = (
                str(registered.get("name") or "")
                if registered else str(row.get("hostname") or "")
            ) or str(row.get("mac") or row.get("target_mac") or "")
            task_client_ip = (
                str(registered.get("ip") or "")
                if registered else str(
                    row.get("registered_ip") or row.get("client_ip")
                    or row.get("identity_ip") or ""
                )
            )
            values = [
                row.get("id", ""),
                "下发" if row.get("action") == "deploy" else "上传",
                (
                    transfer_mode_text(str(row.get("transfer_mode") or "unicast"))
                    if row.get("action") == "deploy" else "单独上传"
                ),
                row.get("image_name", ""), row.get("device", ""),
                post_action_text(str(row.get("post_action") or "none")),
                row.get("status", ""),
                task_client_name,
                task_client_ip,
                row.get("target_group", ""),
                (
                    f"{float(row.get('progress_percent') or 0):.1f}%"
                    if row.get("action") == "deploy" else "-"
                ),
                f"{int(row.get('received_bytes', 0)) / 1024 / 1024:.1f} MiB",
                row.get("started_at", ""),
                format_duration(row.get("elapsed_seconds")) if row.get("started_at") else "",
                (
                    {
                        "pending": "待写入",
                        "scheduled": "待首次启动应用",
                        "applied_offline": "已离线写入",
                        "applied": "已应用",
                        "failed": "执行失败",
                    }.get(str(row.get("identity_status")), "不修改")
                ),
                row.get("message", ""), row.get("created_at", ""),
            ]
            for column, value in enumerate(values):
                self.table.setItem(index, column, QTableWidgetItem(str(value)))
            if str(row.get("id") or "") in selected_task_ids:
                for column in range(self.table.columnCount()):
                    item = self.table.item(index, column)
                    if item:
                        item.setSelected(True)
        self.header_summary.setText(
            f"客户端 {len(self.store.registrations())}　任务 {len(rows)}"
        )
        self.log.setPlainText(self.pxe.log_text(reverse=True))
        self.log.moveCursor(QTextCursor.Start)
        self.log.ensureCursorVisible()

    def closeEvent(self, event):
        self.stop_services()
        event.accept()


def main():
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
