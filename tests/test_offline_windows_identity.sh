#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=/tmp/zos-offline-ip-regression
rm -rf "$test_root"
rm -f /tmp/zos-test-static-import.reg
rm -f /tmp/zos-test-dhcp-import.reg
rm -f /tmp/zos-test-network-mode
rm -f /tmp/zos-test-software-import.reg
rm -f /tmp/zos-test-direct-network.cmd
rm -f /tmp/zos-test-direct-network.ps1
rm -f /tmp/zos-test-direct-system.hive
rm -f /tmp/zos-test-direct-software.hive
mkdir -p "$test_root/Windows/System32/config"
touch "$test_root/Windows/System32/config/SYSTEM"
touch "$test_root/Windows/System32/config/SOFTWARE"

export PATH="$project_dir/tests:$PATH"
export ZOS_AGENT_LIBRARY_ONLY=1
source "$project_dir/boot/zos/jingyun-zos-agent"

TASK_ID=offline-ip-test
SERVER=192.168.5.1
PORT=8090
TOKEN=test-token

install_windows_identity \
    "$test_root" "balabala1" "192.168.5.101" "24" "192.168.5.254" \
    "223.6.6.6,114.114.114.114" \
    "00:0c:29:8c:ff:6f"

[[ "$IDENTITY_MESSAGE" == *"one-time MAC verification staged"* ]]
grep -q '"EnableDHCP"=dword:00000000' /tmp/zos-test-static-import.reg
grep -q '"IPAutoconfigurationEnabled"=dword:00000000' /tmp/zos-test-static-import.reg
grep -q '"IPAddress"=hex(7):31,00,39,00,32,00,2e,00,31,00,36,00,38,00,2e,00,35,00,2e,00,31,00,30,00,31,00,00,00,00,00' \
    /tmp/zos-test-static-import.reg
grep -q '"SubnetMask"=hex(7):32,00,35,00,35,00,2e,00,32,00,35,00,35,00,2e,00,32,00,35,00,35,00,2e,00,30,00,00,00,00,00' \
    /tmp/zos-test-static-import.reg
grep -q 'Interfaces\\{11111111-2222-3333-4444-555555555555}' \
    /tmp/zos-test-static-import.reg
grep -q '"ZOSApplyNetwork"=' /tmp/zos-test-software-import.reg
grep -q 'Get-WmiObject Win32_NetworkAdapterConfiguration' \
    "$test_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q 'Static IPv4 verification failed after EnableStatic' \
    "$test_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q '\$Gateway = "192.168.5.254"' \
    "$test_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q '\$DnsText = "223.6.6.6,114.114.114.114"' \
    "$test_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q 'del /f /q C:\\Windows\\Temp\\ZOSApplyNetwork.ps1' \
    "$test_root/Windows/Temp/ZOSApplyNetwork.cmd"

install_windows_identity_direct \
    "/dev/zos-test-ntfs" "balabala1" "192.168.5.101" "24" "192.168.5.254" \
    "223.6.6.6,114.114.114.114" \
    "00:0c:29:8c:ff:6f"

grep -q 'powershell.exe' /tmp/zos-test-direct-network.cmd
grep -q 'Get-WmiObject Win32_NetworkAdapterConfiguration' \
    /tmp/zos-test-direct-network.ps1
[[ -s /tmp/zos-test-direct-system.hive ]]
[[ -s /tmp/zos-test-direct-software.hive ]]

name_root=/tmp/zos-name-only-regression
rm -rf "$name_root"
mkdir -p "$name_root/Windows/System32/config"
touch "$name_root/Windows/System32/config/SYSTEM"
install_windows_identity \
    "$name_root" "balabala1" "" "24" "" "" "00:0c:29:8c:ff:6f"
[[ "$IDENTITY_MESSAGE" == *"network configuration was preserved"* ||
   "$IDENTITY_MESSAGE" == *"early offline personalization"* ]]
[[ ! -e "$name_root/Windows/Temp/ZOSApplyNetwork.ps1" ]]

ip_root=/tmp/zos-ip-only-regression
rm -rf "$ip_root"
mkdir -p "$ip_root/Windows/System32/config"
touch "$ip_root/Windows/System32/config/SYSTEM"
touch "$ip_root/Windows/System32/config/SOFTWARE"
install_windows_identity \
    "$ip_root" "" "192.168.5.101" "24" "192.168.5.254" \
    "223.6.6.6,114.114.114.114" "00:0c:29:8c:ff:6f"
[[ "$IDENTITY_MESSAGE" == *"computer name preserved"* ]]
[[ -s "$ip_root/Windows/Temp/ZOSApplyNetwork.ps1" ]]

dhcp_root=/tmp/zos-dhcp-regression
rm -rf "$dhcp_root"
mkdir -p "$dhcp_root/Windows/System32/config"
touch "$dhcp_root/Windows/System32/config/SYSTEM"
touch "$dhcp_root/Windows/System32/config/SOFTWARE"
install_windows_identity \
    "$dhcp_root" "" "" "24" "" "" "00:0c:29:8c:ff:6f" "dhcp"
[[ "$IDENTITY_MESSAGE" == *"DHCP and automatic DNS"* ]]
grep -q '"EnableDHCP"=dword:00000001' /tmp/zos-test-dhcp-import.reg
grep -q '"IPAutoconfigurationEnabled"=dword:00000001' /tmp/zos-test-dhcp-import.reg
grep -q '\$NetworkMode = "dhcp"' "$dhcp_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q '\$adapter.EnableDHCP()' "$dhcp_root/Windows/Temp/ZOSApplyNetwork.ps1"
grep -q 'SetDNSServerSearchOrder(\$null)' "$dhcp_root/Windows/Temp/ZOSApplyNetwork.ps1"

printf '%s\n' "offline Windows name/static-IP/DHCP registry test passed"
