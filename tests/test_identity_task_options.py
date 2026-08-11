#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
from pathlib import Path


project = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project))

dummy = type("QtDummy", (), {})
pyqt = types.ModuleType("PyQt5")
qtcore = types.ModuleType("PyQt5.QtCore")
qtgui = types.ModuleType("PyQt5.QtGui")
qtwidgets = types.ModuleType("PyQt5.QtWidgets")
qtcore.QTimer = dummy
qtcore.Qt = dummy
qtgui.QTextCursor = type("QTextCursor", (), {"Start": 0})
for name in (
    "QAbstractItemView", "QApplication", "QCheckBox", "QComboBox", "QDialog",
    "QDialogButtonBox", "QFileDialog", "QFormLayout", "QFrame", "QHBoxLayout",
    "QHeaderView", "QLabel",
    "QLineEdit", "QMainWindow", "QMessageBox", "QPushButton", "QTableWidget",
    "QTableWidgetItem", "QTextEdit", "QVBoxLayout", "QWidget",
):
    setattr(qtwidgets, name, dummy)
sys.modules.update({
    "PyQt5": pyqt,
    "PyQt5.QtCore": qtcore,
    "PyQt5.QtGui": qtgui,
    "PyQt5.QtWidgets": qtwidgets,
})

spec = importlib.util.spec_from_file_location(
    "zos_manager_identity_test", project / "jingyun_simple_manager.py"
)
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

with tempfile.TemporaryDirectory(prefix="zos-identity-options-") as temporary:
    root = Path(temporary)
    manager.DATA_DIR = root / "data"
    manager.IMAGE_DIR = root / "images"
    manager.TASK_FILE = manager.DATA_DIR / "tasks.json"
    manager.NODE_FILE = manager.DATA_DIR / "nodes.json"
    manager.REGISTRATION_FILE = manager.DATA_DIR / "registrations.json"
    manager.IMAGE_DIR.mkdir(parents=True)
    image = manager.IMAGE_DIR / "template.img.zst"
    image.write_bytes(b"ZOS")
    image.with_suffix(".zst.json").write_text(
        json.dumps({"image_type": "raw_disk", "source_bytes": 1024}),
        encoding="utf-8",
    )
    store = manager.JsonTaskStore()
    common = {
        "image_file": image.name,
        "target_mac": "00:0c:29:8c:ff:6f",
    }

    dhcp_only = store.create_deploy_task(**common, identity={
        "apply_name": False, "apply_ip": False, "network_mode": "dhcp",
    })
    assert dhcp_only["apply_computer_name"] is False
    assert dhcp_only["apply_static_ip"] is False
    assert dhcp_only["apply_registered_identity"] is True
    assert dhcp_only["identity_network_mode"] == "dhcp"
    assert dhcp_only["identity_name"] == ""
    assert dhcp_only["identity_ip"] == ""

    name_only = store.create_deploy_task(**common, identity={
        "enabled": True, "apply_name": True, "apply_ip": False,
        "network_mode": "dhcp", "name": "PC-001",
    })
    assert name_only["apply_computer_name"] is True
    assert name_only["apply_static_ip"] is False
    assert name_only["identity_name"] == "PC-001"
    assert name_only["identity_ip"] == ""
    assert name_only["identity_network_mode"] == "dhcp"

    ip_only = store.create_deploy_task(**common, identity={
        "enabled": True, "apply_name": False, "apply_ip": True,
        "ip": "192.168.5.100", "prefix": 24,
        "gateway": "192.168.5.254",
        "dns": ["223.6.6.6", "114.114.114.114"],
    })
    assert ip_only["apply_computer_name"] is False
    assert ip_only["apply_static_ip"] is True
    assert ip_only["identity_name"] == ""
    assert ip_only["identity_ip"] == "192.168.5.100"
    assert ip_only["identity_gateway"] == "192.168.5.254"
    assert ip_only["identity_dns"] == ["223.6.6.6", "114.114.114.114"]
    assert ip_only["identity_network_mode"] == "static"

    both = store.create_deploy_task(**common, identity={
        "enabled": True, "apply_name": True, "apply_ip": True,
        "name": "PC-002", "ip": "192.168.5.101", "prefix": 24,
        "gateway": "", "dns": [],
    })
    assert both["apply_computer_name"] is True
    assert both["apply_static_ip"] is True
    assert both["identity_name"] == "PC-002"
    assert both["identity_ip"] == "192.168.5.101"
    assert both["identity_gateway"] == ""
    assert both["identity_dns"] == []
    assert both["identity_network_mode"] == "static"

print("separate computer-name/static-IP/DHCP task option test passed")
