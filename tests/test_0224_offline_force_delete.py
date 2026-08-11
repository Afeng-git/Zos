from pathlib import Path
import ast


def manager_source():
    root = Path(__file__).resolve().parents[1]
    return (root / 'jingyun_simple_manager.py').read_text(encoding='utf-8')


def test_force_delete_supported():
    source = manager_source()
    assert 'def delete_tasks(self, task_ids: list[str], force: bool = False)' in source
    assert 'self.store.delete_tasks(task_ids, force=True)' in source
    assert 'self.store.delete_tasks(all_ids, force=True)' in source
    assert '任务仍标记为执行中' in source
    assert '是否强制清空全部任务' in source


def test_multicast_no_online_install_prompt():
    source = manager_source()
    # UI no longer offers online package installation on an isolated deployment LAN.
    assert '是否现在自动安装 udpcast' not in source
    assert '本程序不会再尝试 apt/yum 在线安装' in source
    assert 'client_arches not in ({"arm64"}, {"loongarch64"})' in source


def test_manager_still_parses():
    ast.parse(manager_source())
