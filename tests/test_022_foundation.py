from pathlib import Path


def test_022_version_and_catalog_foundation():
    root = Path(__file__).resolve().parents[1]
    manager = (root / 'jingyun_simple_manager.py').read_text(encoding='utf-8')
    shell_agent = (root / 'boot/zos/jingyun-zos-agent').read_text(encoding='utf-8')
    loong_agent = (root / 'boot/zos/jingyun-zos-agent-loongarch64.py').read_text(encoding='utf-8')
    assert 'VERSION = "0.22.6"' in manager
    assert 'IMAGE_CATALOG_FILE' in manager
    assert 'def rebuild_image_catalog()' in manager
    assert 'VERSION="0.22.6"' in shell_agent
    assert 'VERSION = "0.22.6"' in loong_agent
    assert '/etc/netplan/99-zos-identity.yaml' in loong_agent
