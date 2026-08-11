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

    def __getattr__(self, name):
        if name in {"clicked", "currentIndexChanged", "cellDoubleClicked"}:
            return DummySignal()
        return lambda *_args, **_kwargs: Dummy()


class DummySignal:
    def connect(self, _callback):
        return None


project = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project))
pyqt = types.ModuleType("PyQt5")
qtcore = types.ModuleType("PyQt5.QtCore")
qtgui = types.ModuleType("PyQt5.QtGui")
qtwidgets = types.ModuleType("PyQt5.QtWidgets")
qtcore.QTimer = Dummy
qtcore.Qt = Dummy
qtgui.QTextCursor = Dummy
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

spec = importlib.util.spec_from_file_location("zos_manager_ui_test", project / "jingyun_simple_manager.py")
assert spec and spec.loader
manager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager)

window = object.__new__(manager.MainWindow)
window.config = manager.default_config()
window.refresh_group_filter = lambda: None
window._build()

for attribute in (
    "start_button", "stop_button", "edit_clients_button", "import_clients_button",
    "export_clients_button", "delete_clients_button", "delete_tasks_button", "clear_tasks_button",
    "client_table", "table", "log",
):
    assert hasattr(window, attribute), attribute
assert "QFrame#sidebar" in manager.MODERN_STYLE
assert "QFrame#card" in manager.MODERN_STYLE

print("modern PyQt5 UI construction test passed")
