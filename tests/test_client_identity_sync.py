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
    "QHeaderView", "QLabel", "QLineEdit", "QMainWindow", "QMessageBox",
    "QPushButton", "QTableWidget", "QTableWidgetItem", "QTextEdit", "QVBoxLayout",
    "QWidget",
):
    setattr(qtwidgets, name, dummy)
sys.modules.update({
    "PyQt5": pyqt,
    "PyQt5.QtCore": qtcore,
    "PyQt5.QtGui": qtgui,
    "PyQt5.QtWidgets": qtwidgets,
})

spec = importlib.util.spec_from_file_location(
    "zos_manager_client_identity_test", project / "jingyun_simple_manager.py"
)
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

with tempfile.TemporaryDirectory(prefix="zos-client-identity-") as temporary:
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
        json.dumps({
            "image_type": "raw_disk",
            "source_bytes": 1024,
            "source_arch": "unknown",
        }),
        encoding="utf-8",
    )

    store = manager.JsonTaskStore()
    mac = "00:0c:29:11:22:33"
    created, updated = store.import_registrations([{
        "mac": mac,
        "name": "PC-001",
        "ip": "192.168.5.101",
        "group": "一组",
    }])
    assert (created, updated) == (1, 0)

    task = store.create_deploy_task(
        image.name,
        target_mac=mac,
        identity={
            "enabled": True,
            "apply_name": True,
            "apply_ip": True,
            "name": "PC-001",
            "ip": "192.168.5.101",
            "prefix": 24,
        },
    )
    assert task["hostname"] == "PC-001"
    assert task["client_ip"] == "192.168.5.101"

    count = store.update_registration_identities([{
        "mac": mac,
        "name": "PC-002",
        "ip": "192.168.5.102",
    }])
    assert count == 1
    registration = store.registrations()[0]
    assert registration["name"] == "PC-002"
    assert registration["ip"] == "192.168.5.102"
    assert registration["identity_locked"] is True

    queued = store.tasks()[0]
    assert queued["hostname"] == "PC-002"
    assert queued["client_ip"] == "192.168.5.102"
    assert queued["identity_name"] == "PC-002"
    assert queued["identity_ip"] == "192.168.5.102"

    claimed = store.claim({
        "mac": mac,
        "mode": "deploy",
        "automatic": True,
        "hostname": "temporary-pxe-name",
        "ip": "192.168.50.101",
        "inventory": {"arch": "x86_64", "disks": []},
    })
    assert claimed is not None
    assert claimed["client_ip"] == "192.168.5.102"
    assert claimed["reported_ip"] == "192.168.50.101"
    assert claimed["hostname"] == "PC-002"

    # A later PXE registration must not overwrite a manually/imported identity.
    registered_again = store.register_client({
        "mac": mac,
        "hostname": "pxe-host",
        "name": "PXE-NAME",
        "group": "二组",
        "ip": "192.168.50.102",
        "inventory": {"arch": "x86_64", "disks": []},
    })
    assert registered_again["name"] == "PC-002"
    assert registered_again["group"] == "一组"
    assert registered_again["ip"] == "192.168.5.102"
    assert registered_again["reported_ip"] == "192.168.50.102"


    # Existing 0.21.11 records without the new lock flag are also authoritative after upgrade.
    legacy_mac = "00:0c:29:44:55:66"
    legacy_rows = store.registrations()
    legacy_rows.append({
        "mac": legacy_mac,
        "name": "LEGACY-01",
        "ip": "192.168.5.120",
        "group": "旧组",
        "registered_at": "2026-08-01 10:00:00",
    })
    manager.atomic_json(manager.REGISTRATION_FILE, legacy_rows)
    legacy_again = store.register_client({
        "mac": legacy_mac,
        "hostname": "pxe-legacy",
        "name": "SHOULD-NOT-REPLACE",
        "group": "新组",
        "ip": "192.168.50.120",
        "inventory": {"arch": "x86_64", "disks": []},
    })
    assert legacy_again["name"] == "LEGACY-01"
    assert legacy_again["group"] == "旧组"
    assert legacy_again["ip"] == "192.168.5.120"
    assert legacy_again["reported_ip"] == "192.168.50.120"

    # Active tasks protect identity from being changed mid-write/after assignment.
    try:
        store.update_registration_identities([{
            "mac": mac,
            "name": "PC-003",
            "ip": "192.168.5.103",
        }])
    except ValueError as exc:
        assert "正在执行或已经领取任务" in str(exc)
    else:
        raise AssertionError("active task identity edit should be rejected")

source = (project / "jingyun_simple_manager.py").read_text(encoding="utf-8")
assert 'QPushButton("修改IP/计算机名")' in source
assert "class ClientIdentityEditDialog" in source
assert "def update_registration_identities" in source
assert '"reported_ip"' in source
print("registered identity, task IP synchronization and edit action test passed")
