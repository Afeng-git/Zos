#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export ZOS_AGENT_LIBRARY_ONLY=1
source "$project_dir/boot/zos/jingyun-zos-agent"

root=/tmp/zos-deepin25-solid
rm -rf "$root"
data_id=$(printf 'a%.0s' {1..64}).0
mkdir -p \
    "$root/overlay/data/layer-upper" \
    "$root/overlay/data/$data_id/etc-work" \
    "$root/overlay/data/$data_id/usr-upper"
TASK_ID=deepin25-test
SERVER=192.168.5.1
PORT=8090
TOKEN=test-token

install_deepin_solid_overlay_tree \
    "$root/overlay/data" "DEEPIN-01" "192.168.5.121" "24" \
    "192.168.5.254" "223.6.6.6,114.114.114.114" \
    "00:11:22:33:44:55" "static"

[[ "$DEEPIN_SOLID_LAYER_COUNT" == 2 ]]
for etc_root in \
    "$root/overlay/data/layer-upper/etc" \
    "$root/overlay/data/$data_id/etc-upper"; do
    [[ $(cat "$etc_root/hostname") == "DEEPIN-01" ]]
    profile="$etc_root/NetworkManager/system-connections/zos-identity-001122334455.nmconnection"
    test -f "$profile"
    [[ $(stat -c '%a' "$profile") == 600 ]]
    grep -q '^autoconnect-priority=999$' "$profile"
    grep -q '^mac-address=00:11:22:33:44:55$' "$profile"
    grep -q '^address1=192.168.5.121/24,192.168.5.254$' "$profile"
    grep -q '^dns=223.6.6.6;114.114.114.114;$' "$profile"
    test -x "$etc_root/zos/zos-firstboot-identity.sh"
    bash -n "$etc_root/zos/zos-firstboot-identity.sh"
    grep -q '^Before=network-online.target$' \
        "$etc_root/systemd/system/zos-firstboot-identity.service"
    grep -q 'ExecStart=/bin/bash /etc/zos/zos-firstboot-identity.sh' \
        "$etc_root/systemd/system/zos-firstboot-identity.service"
done

grep -q 'persistent/overlay/data' "$project_dir/boot/zos/jingyun-zos-agent"
grep -q 'etc-upper' "$project_dir/boot/zos/jingyun-zos-agent"

printf '%s\n' "deepin 25 Solid upper/lower modification-layer identity test passed"
