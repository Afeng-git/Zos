from pathlib import Path


def test_arm_agent_starts_zosmc_receiver_while_manager_is_starting():
    text = Path('boot/zos/jingyun-zos-agent').read_text(encoding='utf-8')
    assert '( "$multicast_state" == "starting" && "$multicast_protocol" == "zosmc1" )' in text
    assert "printf '\\rMulticast group ready:" in text
    assert 'zosmc-receiver' in text


def test_zosmc_handshake_timeout_is_bounded():
    text = Path('jingyun_simple_manager.py').read_text(encoding='utf-8')
    assert '"zosmc_handshake_timeout": 60' in text
    assert 'max(10, min(300, int(self.config.get("zosmc_handshake_timeout", 60))))' in text
