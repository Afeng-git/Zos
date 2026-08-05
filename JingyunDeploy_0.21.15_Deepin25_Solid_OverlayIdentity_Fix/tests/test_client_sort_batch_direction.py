#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


class DummyItem:
    def __init__(self, *_args, **_kwargs):
        pass

    def __lt__(self, _other):
        return False


class Dummy:
    pass


project = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project))
pyqt = types.ModuleType("PyQt5")
qtcore = types.ModuleType("PyQt5.QtCore")
qtgui = types.ModuleType("PyQt5.QtGui")
qtwidgets = types.ModuleType("PyQt5.QtWidgets")
qtcore.QTimer = Dummy
qtcore.Qt = Dummy
qtgui.QTextCursor = type("QTextCursor", (), {"Start": 0})
for name in (
    "QAbstractItemView", "QApplication", "QCheckBox", "QComboBox", "QDialog",
    "QDialogButtonBox", "QFileDialog", "QFormLayout", "QFrame", "QHBoxLayout",
    "QHeaderView", "QLabel", "QLineEdit", "QMainWindow", "QMessageBox",
    "QPushButton", "QTableWidget", "QTextEdit", "QVBoxLayout", "QWidget",
):
    setattr(qtwidgets, name, Dummy)
qtwidgets.QTableWidgetItem = DummyItem
sys.modules.update({
    "PyQt5": pyqt,
    "PyQt5.QtCore": qtcore,
    "PyQt5.QtGui": qtgui,
    "PyQt5.QtWidgets": qtwidgets,
})

spec = importlib.util.spec_from_file_location(
    "zos_manager_sort_batch_test", project / "jingyun_simple_manager.py"
)
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

assert manager.natural_sort_key("PC-2") < manager.natural_sort_key("PC-10")
assert manager.client_table_sort_key(2, "192.168.5.9") < manager.client_table_sort_key(2, "192.168.5.100")
assert manager.client_table_sort_key(5, "2") < manager.client_table_sort_key(5, "10")

clients = [
    {"mac": "00:00:00:00:00:01", "name": "OLD-1", "ip": "192.168.5.11"},
    {"mac": "00:00:00:00:00:02", "name": "OLD-2", "ip": "192.168.5.12"},
    {"mac": "00:00:00:00:00:03", "name": "OLD-3", "ip": "192.168.5.13"},
]
assert [row["mac"] for row in manager.clients_in_batch_direction(clients, "forward")] == [
    "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"
]
assert [row["mac"] for row in manager.clients_in_batch_direction(clients, "reverse")] == [
    "00:00:00:00:00:03", "00:00:00:00:00:02", "00:00:00:00:00:01"
]


class Check:
    def isChecked(self):
        return True


class Text:
    def __init__(self, value):
        self.value = value

    def text(self):
        return self.value


class Combo:
    def __init__(self, value):
        self.value = value

    def currentData(self):
        return self.value


def build(direction: str):
    dialog = object.__new__(manager.ClientIdentityEditDialog)
    dialog.clients = [dict(row) for row in clients]
    dialog.subnet_mask = "255.255.255.0"
    dialog.single = False
    dialog.apply_name = Check()
    dialog.apply_ip = Check()
    dialog.assignment_order = Combo(direction)
    dialog.name_prefix = Text("PC-")
    dialog.name_start = Text("1")
    dialog.name_digits = Text("3")
    dialog.ip_start = Text("192.168.5.101")
    return dialog.build_updates()

forward = {row["mac"]: row for row in build("forward")}
assert forward["00:00:00:00:00:01"]["name"] == "PC-001"
assert forward["00:00:00:00:00:01"]["ip"] == "192.168.5.101"
assert forward["00:00:00:00:00:03"]["name"] == "PC-003"

reverse = {row["mac"]: row for row in build("reverse")}
assert reverse["00:00:00:00:00:03"]["name"] == "PC-001"
assert reverse["00:00:00:00:00:03"]["ip"] == "192.168.5.101"
assert reverse["00:00:00:00:00:01"]["name"] == "PC-003"

source = (project / "jingyun_simple_manager.py").read_text(encoding="utf-8")
assert "setSortingEnabled(True)" in source
assert 'addItem("正序（当前列表从上到下）", "forward")' in source
assert 'addItem("倒序（当前列表从下到上）", "reverse")' in source
assert "rows_by_mac" in source
print("client header sorting and forward/reverse batch assignment test passed")
