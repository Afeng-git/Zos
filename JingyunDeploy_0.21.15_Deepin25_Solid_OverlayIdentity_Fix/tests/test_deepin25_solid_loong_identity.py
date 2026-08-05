from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
AGENT = PROJECT / "boot/zos/jingyun-zos-agent-loongarch64.py"
spec = importlib.util.spec_from_file_location("zos_loong_agent", AGENT)
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
    "identity_name": "DEEPIN-L01",
    "identity_ip": "192.168.5.122",
    "identity_prefix": 24,
    "identity_gateway": "192.168.5.254",
    "identity_dns": ["223.6.6.6", "114.114.114.114"],
}

with tempfile.TemporaryDirectory(prefix="zos-deepin-solid-loong-") as temporary:
    overlay = Path(temporary) / "overlay/data"
    (overlay / "layer-top").mkdir(parents=True)
    data_id = "b" * 64 + ".0"
    (overlay / data_id / "etc-work").mkdir(parents=True)
    count = agent.install_deepin_solid_overlay_tree(
        overlay, task, "AA:BB:CC:DD:EE:11"
    )
    assert count == 2
    for etc_root in (overlay / "layer-top/etc", overlay / data_id / "etc-upper"):
        assert (etc_root / "hostname").read_text().strip() == "DEEPIN-L01"
        profile = etc_root / (
            "NetworkManager/system-connections/"
            "zos-identity-aabbccddee11.nmconnection"
        )
        text = profile.read_text()
        assert "autoconnect-priority=999" in text
        assert "address1=192.168.5.122/24,192.168.5.254" in text
        assert "dns=223.6.6.6;114.114.114.114;" in text
        assert profile.stat().st_mode & 0o777 == 0o600
        service = etc_root / "systemd/system/zos-firstboot-identity.service"
        assert "Before=network-online.target" in service.read_text()

print("deepin 25 Solid LoongArch64 modification-layer identity test passed")
