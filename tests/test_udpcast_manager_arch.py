from pathlib import Path


def test_manager_has_arm_and_loong_udpcast_paths():
    root = Path(__file__).resolve().parents[1]
    text = (root / "jingyun_simple_manager.py").read_text(encoding="utf-8")
    assert 'linux-aarch64' in text
    assert 'linux-loongarch64' in text
    assert 'install_udpcast' in text
    assert 'apt-get' in text
    assert 'zypper' in text
