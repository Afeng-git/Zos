#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
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
    "PyQt5": pyqt, "PyQt5.QtCore": qtcore,
    "PyQt5.QtGui": qtgui, "PyQt5.QtWidgets": qtwidgets,
})

spec = importlib.util.spec_from_file_location("zos_manager_import_test", project / "jingyun_simple_manager.py")
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

with tempfile.TemporaryDirectory(prefix="zos-client-import-") as temporary:
    root = Path(temporary)
    manager.DATA_DIR = root / "data"
    manager.IMAGE_DIR = root / "images"
    manager.TASK_FILE = manager.DATA_DIR / "tasks.json"
    manager.NODE_FILE = manager.DATA_DIR / "nodes.json"
    manager.REGISTRATION_FILE = manager.DATA_DIR / "registrations.json"

    xlsx = root / "clients.xlsx"
    manager.write_xlsx(
        xlsx,
        ["状态", "客户端名称", "IP", "MAC", "组"],
        [
            ["已注册", "PC-01", "192.168.5.101", "00:0C:29:11:22:33", "一组"],
            ["已注册", "PC-02", "192.168.5.102", "00-0C-29-44-55-66", "二组"],
            ["已注册", "BAD", "999.1.1.1", "bad-mac", "二组"],
        ],
    )
    imported, errors = manager.parse_client_import(xlsx)
    assert len(imported) == 2
    assert len(errors) == 1
    assert imported[0]["mac"] == "00:0c:29:11:22:33"
    assert imported[1]["group"] == "二组"

    text_file = root / "clients.txt"
    text_file.write_text(
        "计算机名\tIP地址\tMAC地址\t分组\n"
        "PC-03\t192.168.5.103\t00:0c:29:77:88:99\t三组\n",
        encoding="utf-8-sig",
    )
    text_rows, text_errors = manager.parse_client_import(text_file)
    assert len(text_rows) == 1 and not text_errors

    store = manager.JsonTaskStore()
    created, updated = store.import_registrations(imported)
    assert (created, updated) == (2, 0)
    changed = [dict(imported[0], name="PC-01-NEW", ip="192.168.5.111")]
    created, updated = store.import_registrations(changed)
    assert (created, updated) == (0, 1)
    first = next(row for row in store.registrations() if row["mac"] == changed[0]["mac"])
    assert first["name"] == "PC-01-NEW" and first["ip"] == "192.168.5.111"

    store._save_tasks([
        {"id": "single", "target_mac": changed[0]["mac"], "status": "queued"},
        {"id": "mc1", "target_mac": imported[1]["mac"], "status": "queued", "multicast_session_id": "session-a"},
        {"id": "mc2", "target_mac": "00:0c:29:aa:bb:cc", "status": "queued", "multicast_session_id": "session-a"},
    ])
    assert store.delete_registrations([changed[0]["mac"]]) == 1
    assert next(row for row in store.tasks() if row["id"] == "single")["status"] == "cancelled"
    deleted, sessions = store.delete_tasks(["mc1"])
    assert deleted == 2 and sessions == ["session-a"]
    assert [row["id"] for row in store.tasks()] == ["single"]

print("client xlsx/txt import and batch deletion test passed")
