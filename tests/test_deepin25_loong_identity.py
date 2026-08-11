from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

project = Path(__file__).resolve().parents[1]
agent_path = project / "boot/zos/jingyun-zos-agent-loongarch64.py"
spec = importlib.util.spec_from_file_location("zos_deepin25_loong_test", agent_path)
assert spec and spec.loader
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

agent.SERVER = "192.168.5.1"
agent.PORT = 8090
agent.TOKEN = "test-token"
agent.TASK_ID = "deepin25-loong-test"

task = {
    "apply_registered_identity": True,
    "apply_computer_name": True,
    "apply_static_ip": True,
    "identity_network_mode": "static",
    "identity_name": "DEEPIN-L-01",
    "identity_ip": "192.168.5.131",
    "identity_prefix": 24,
    "identity_gateway": "192.168.5.254",
    "identity_dns": ["223.6.6.6", "114.114.114.114"],
}

with tempfile.TemporaryDirectory(prefix="zos-deepin25-loong-") as temporary:
    root = Path(temporary) / "ostree/deploy/deepin/deploy/abcdef.0"
    (root / "etc").mkdir(parents=True)
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/os-release").write_text("ID=deepin\nVERSION_ID=25.2.0\n")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n")
    agent.install_linux_identity(root, task, "00:11:22:33:44:66")
    assert (root / "etc/hostname").read_text().strip() == "DEEPIN-L-01"
    script = (root / "etc/zos/zos-firstboot-identity.sh").read_text()
    assert "nmcli connection add type ethernet" in script
    service = (root / "etc/systemd/system/zos-firstboot-identity.service").read_text()
    assert "ExecStart=/bin/bash /etc/zos/zos-firstboot-identity.sh" in service

source = agent_path.read_text()
assert 'glob("ostree/deploy/*/deploy/*.0")' in source
print("deepin 25 LoongArch64 immutable identity test passed")
