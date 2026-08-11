from pathlib import Path


def test_hardware_inventory_and_warning_only_flow():
    root = Path(__file__).resolve().parents[1]
    manager = (root / 'jingyun_simple_manager.py').read_text(encoding='utf-8')
    shell_agent = (root / 'boot/zos/jingyun-zos-agent').read_text(encoding='utf-8')
    loong_agent = (root / 'boot/zos/jingyun-zos-agent-loongarch64.py').read_text(encoding='utf-8')
    assert 'cpu_model' in shell_agent and 'cpu_cores' in shell_agent and 'memory_bytes' in shell_agent
    assert 'cpu_model' in loong_agent and 'cpu_cores' in loong_agent and 'memory_bytes' in loong_agent
    assert 'CPU架构不匹配' in manager
    assert '这只是兼容性提示' in manager
    assert '禁止下发' not in manager
    assert '已阻止写盘' not in manager
    assert 'group_mismatches' in manager
    assert 'multicast_expected=len(clients)' in manager
