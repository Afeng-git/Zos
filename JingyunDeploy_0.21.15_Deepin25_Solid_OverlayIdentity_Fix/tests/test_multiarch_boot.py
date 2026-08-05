#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


class DummyMeta(type):
    def __getattr__(cls, _name):
        return 0


class Dummy(metaclass=DummyMeta):
    def __init__(self, *_args, **_kwargs):
        pass


project = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project))

pyqt = types.ModuleType("PyQt5")
qtcore = types.ModuleType("PyQt5.QtCore")
qtgui = types.ModuleType("PyQt5.QtGui")
qtwidgets = types.ModuleType("PyQt5.QtWidgets")
qtcore.QTimer = qtcore.Qt = qtgui.QTextCursor = Dummy
for name in (
    "QAbstractItemView", "QApplication", "QCheckBox", "QComboBox", "QDialog",
    "QDialogButtonBox", "QFileDialog", "QFormLayout", "QFrame", "QHBoxLayout",
    "QHeaderView", "QLabel", "QLineEdit", "QMainWindow", "QMessageBox",
    "QPushButton", "QTableWidget", "QTableWidgetItem", "QTextEdit", "QVBoxLayout",
    "QWidget",
):
    setattr(qtwidgets, name, Dummy)
sys.modules.update({
    "PyQt5": pyqt, "PyQt5.QtCore": qtcore,
    "PyQt5.QtGui": qtgui, "PyQt5.QtWidgets": qtwidgets,
})

spec = importlib.util.spec_from_file_location("zos_manager_multiarch_test", project / "jingyun_simple_manager.py")
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

from server.pxe_services import MAINTENANCE_FILES, boot_filename


assert boot_filename(0, b"", "192.0.2.1", 8090) == "undionly.kpxe"
assert boot_filename(11, b"", "192.0.2.1", 8090) == "snponly-arm64.efi"
assert boot_filename(0x27, b"", "192.0.2.1", 8090) == "snponly-loongarch64.efi"
assert boot_filename(10, b"", "192.0.2.1", 8090) == ""
assert boot_filename(0x7FFF, b"", "192.0.2.1", 8090) == ""
assert boot_filename(0x27, b"iPXE", "192.0.2.1", 8090) == "boot.ipxe"

routing = manager.ipxe_architecture_setup()
for value in ("${buildarch}", ":arch_arm64", ":arch_loong64", "set zos_arch x86_64"):
    assert value in routing
assert "set zos_arch loongarch64" in routing
assert "set zos_kernel Image" in routing
assert "set zos_init init.cpio.gz" in routing
assert "initrd=${zos_init}" in routing
assert "console=ttyAMA0,115200n8" in routing
assert "console=tty0" in routing
assert "set zos_kernel vmlinuz" in routing
assert manager.normalize_architecture("aarch64") == "arm64"
assert manager.normalize_architecture("loong64") == "loongarch64"
assert manager.normalize_architecture("AMD64") == "x86_64"
assert manager.MulticastCoordinator.protocol({
    "rows": [{"source_arch": "loongarch64", "client_arch": "loongarch64"}]
}) == "zosmc1"
assert manager.MulticastCoordinator.protocol({
    "rows": [{"source_arch": "x86_64", "client_arch": "x86_64"}]
}) == "udpcast"
try:
    manager.MulticastCoordinator.protocol({
        "rows": [{"client_arch": "loongarch64"}, {"client_arch": "x86_64"}]
    })
except ValueError:
    pass
else:
    raise AssertionError("mixed-architecture multicast must be rejected")

for relative in MAINTENANCE_FILES:
    path = project / "tftp" / relative
    assert path.is_file() and path.stat().st_size > 1024 * 1024, path

arm_kernel = (project / "tftp/arm64/zos/Image").read_bytes()[:64]
assert arm_kernel[56:60] == b"ARM\x64"
loong_kernel = (project / "tftp/loongarch64/zos/vmlinuz").read_bytes()[:64]
assert loong_kernel[:4] == b"\x7fELF"
assert int.from_bytes(loong_kernel[18:20], "little") == 258


arm_config = (project / "tftp/arm64/zos/Image.config").read_text(encoding="utf-8")
for option in (
    "CONFIG_ACPI=y", "CONFIG_EFI_STUB=y",
    "CONFIG_SERIAL_AMBA_PL011=y", "CONFIG_SERIAL_AMBA_PL011_CONSOLE=y",
    "CONFIG_PCI_HOST_GENERIC=y", "CONFIG_VIRTIO_PCI=y",
    "CONFIG_VIRTIO_NET=y", "CONFIG_VIRTIO_BLK=y",
    "CONFIG_SCSI_VIRTIO=y", "CONFIG_DRM_VIRTIO_GPU=y",
    "CONFIG_DRM_SIMPLEDRM=y", "CONFIG_RD_GZIP=y",
):
    assert option in arm_config, option
assert "# CONFIG_MODULES is not set" in arm_config
assert "Authorization binary is corrupted" not in (project / "tftp/arm64/zos/Image").read_bytes().decode("latin1", "ignore")

manager_source = (project / "jingyun_simple_manager.py").read_text(encoding="utf-8")
assert "initrd --name ${{zos_init}}" in manager_source
s99 = (project / "boot/zos/S99zos").read_text(encoding="utf-8")
assert "read_zos_cmdline" in s99 and "jy_mode=*" in s99
s40 = (project / "boot/zos/S40network").read_text(encoding="utf-8")
assert "/sys/class/net/*" in s40

print("multi-architecture DHCP, iPXE routing and maintenance asset test passed")
