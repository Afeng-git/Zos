#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


project = Path(__file__).resolve().parents[1]
agent_path = project / "boot/zos/jingyun-zos-agent-loongarch64.py"
spec = importlib.util.spec_from_file_location("zos_loong_identity_test", agent_path)
assert spec and spec.loader
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

with tempfile.TemporaryDirectory(prefix="zos-loong-identity-") as temporary:
    root = Path(temporary)
    (root / "etc/systemd/system").mkdir(parents=True)
    (root / "etc/os-release").write_text("ID=kylin\n", encoding="utf-8")
    (root / "etc/hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    task = {
        "apply_registered_identity": True,
        "apply_computer_name": True,
        "apply_static_ip": True,
        "identity_network_mode": "static",
        "identity_name": "loong-pc-01",
        "identity_ip": "192.168.5.151",
        "identity_prefix": 24,
        "identity_gateway": "192.168.5.254",
        "identity_dns": ["223.6.6.6", "114.114.114.114"],
    }
    message = agent.install_linux_identity(root, task, "00:11:22:33:44:55")
    assert "first boot" in message
    assert (root / "etc/hostname").read_text().strip() == "loong-pc-01"
    first_boot = (root / "usr/local/sbin/zos-firstboot-identity.sh").read_text()
    for value in (
        "192.168.5.151", "192.168.5.254", "223.6.6.6,114.114.114.114",
        "00:11:22:33:44:55", "ipv4.method manual",
    ):
        assert value in first_boot
    assert "@NAME@" not in first_boot
    link = root / "etc/systemd/system/multi-user.target.wants/zos-firstboot-identity.service"
    assert link.is_symlink()

print("LoongArch64 Linux hostname/static-IP first-boot identity test passed")
