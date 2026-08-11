from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]


def elf_machine(path: Path) -> int:
    data = path.read_bytes()[:20]
    assert data[:4] == b"\x7fELF"
    little = data[5] == 1
    return int.from_bytes(data[18:20], "little" if little else "big")


def test_native_offline_sender_binaries_exist_for_arm_and_loong():
    arm = ROOT / "tools/udpcast/linux-aarch64/udp-sender"
    loong = ROOT / "tools/udpcast/linux-loongarch64/udp-sender"
    assert arm.is_file() and arm.stat().st_size > 500_000
    assert loong.is_file() and loong.stat().st_size > 500_000
    assert elf_machine(arm) == 183  # EM_AARCH64
    assert elf_machine(loong) == 258  # EM_LOONGARCH


def test_arm_agent_supports_builtin_zosmc_receiver():
    agent = (ROOT / "boot/zos/jingyun-zos-agent").read_text(encoding="utf-8")
    assert 'multicast_protocol=$(jq -r' in agent
    assert 'zosmc-receiver' in agent
    assert '--session-id "$multicast_session_id"' in agent


def test_manager_uses_zosmc_for_arm64_and_loongarch64():
    source = (ROOT / "jingyun_simple_manager.py").read_text(encoding="utf-8")
    assert 'architectures in ({"arm64"}, {"loongarch64"})' in source
    assert 'return "zosmc1"' in source
    assert 'client_arches not in ({"arm64"}, {"loongarch64"})' in source
