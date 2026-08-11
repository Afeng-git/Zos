from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_arm_ipxe_lease_is_forwarded_to_linux():
    manager = (ROOT / "jingyun_simple_manager.py").read_text(encoding="utf-8")
    assert "set zos_netargs jy_client_ip=${net0/ip}" in manager
    assert "${{zos_args}} ${{zos_netargs}} jy_mode=register" in manager
    assert "${{zos_args}} ${{zos_netargs}} jy_mode={mode}" in manager


def test_valid_ipxe_handoff_never_falls_through_to_dhcp():
    script = (ROOT / "boot/zos/S40network").read_text(encoding="utf-8")
    assert "if has_ipxe_lease; then" in script
    assert "DHCP fallback is intentionally disabled" in script
    assert 'write_network_state "$iface" "$jy_client_ip" "ipxe-static"' in script
    ipxe_branch = script.index("if has_ipxe_lease; then")
    dhcp_call = script.index('configure_dhcp "$iface" && exit 0', ipxe_branch)
    disabled_message = script.index("DHCP fallback is intentionally disabled", ipxe_branch)
    assert disabled_message < dhcp_call


def test_agent_does_not_restart_network_on_tcp_failure():
    agent = (ROOT / "boot/zos/jingyun-zos-agent").read_text(encoding="utf-8")
    tcp_start = agent.index("tcp_json() {")
    tcp_end = agent.index("\ndetect_mac() {", tcp_start)
    tcp_block = agent[tcp_start:tcp_end]
    assert "Manager connection attempt ${attempt}/6 failed" in tcp_block
    assert "/etc/init.d/S40network start" not in tcp_block
    assert "Do not restart networking on a TCP failure" in tcp_block


def test_agent_uses_recorded_network_state_before_parsing_busybox_output():
    agent = (ROOT / "boot/zos/jingyun-zos-agent").read_text(encoding="utf-8")
    function_start = agent.index("get_iface_ipv4() {")
    function_end = agent.index("\nbanner() {", function_start)
    block = agent[function_start:function_end]
    assert block.index("/run/zos-network.env") < block.index("ifconfig")
    assert "ZOS_IPV4" in block
    assert "ip -4 -o" not in block


def test_s99_uses_state_file_instead_of_ip_o():
    script = (ROOT / "boot/zos/S99zos").read_text(encoding="utf-8")
    assert "network_state_ready" in script
    assert "/run/zos-network.env" in script
    assert "ip -4 -o" not in script


def test_s99_repairs_known_empty_hardlink_aliases():
    script = (ROOT / "boot/zos/S99zos").read_text(encoding="utf-8")
    assert "/usr/bin/gawk-5.3.2" in script
    assert "ln -s gawk-5.3.2 /usr/bin/gawk" in script
    assert "ln -s gzip /bin/gunzip" in script
