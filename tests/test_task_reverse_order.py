from pathlib import Path

source = (Path(__file__).resolve().parents[1] / "jingyun_simple_manager.py").read_text()
assert "rows = list(reversed(self.store.tasks()))" in source
print("image task newest-first display test passed")
