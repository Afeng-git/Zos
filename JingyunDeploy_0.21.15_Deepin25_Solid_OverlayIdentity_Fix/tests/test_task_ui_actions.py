#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "jingyun_simple_manager.py").read_text(encoding="utf-8")

assert 'QPushButton("删除任务")' in source
assert 'QPushButton("清空任务")' in source
assert 'def clear_all_tasks(self):' in source
assert '不再弹出第二个“设置完成”窗口' in source
register_block = source[source.index("    def register_client_task(self):"):source.index("    def set_group_task(self):")]
assert 'self, "设置完成"' not in register_block
print("task action buttons and streamlined confirmation test passed")
