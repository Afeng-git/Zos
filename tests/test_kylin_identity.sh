#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export ZOS_AGENT_LIBRARY_ONLY=1
source "$project_dir/boot/zos/jingyun-zos-agent"

root=/tmp/zos-kylin-v10-identity
rm -rf "$root"
mkdir -p "$root/etc" "$root/usr/local/sbin" "$root/etc/systemd/system"
printf '%s\n' '127.0.0.1 localhost' >"$root/etc/hosts"
TASK_ID=kylin-test
SERVER=192.168.5.1
PORT=8090
TOKEN=test-token

install_linux_identity \
    "$root" "KYLN-01" "192.168.5.101" "24" "192.168.5.254" \
    "223.6.6.6,114.114.114.114" "00:0c:29:11:22:33" "static"

[[ $(cat "$root/etc/hostname") == "KYLN-01" ]]
grep -q 'MODE="static"' "$root/usr/local/sbin/zos-firstboot-identity.sh"
grep -q 'nmcli --wait 30 connection up' "$root/usr/local/sbin/zos-firstboot-identity.sh"
grep -q 'ExecStart=/bin/bash /usr/local/sbin/zos-firstboot-identity.sh' \
    "$root/etc/systemd/system/zos-firstboot-identity.service"
grep -q 'TimeoutStartSec=120' "$root/etc/systemd/system/zos-firstboot-identity.service"
grep -q 'vgchange -ay' "$project_dir/boot/zos/jingyun-zos-agent"
grep -q 'lvm pvscan --cache' "$project_dir/boot/zos/jingyun-zos-agent"
grep -q 'mount -t xfs -o rw,nouuid' "$project_dir/boot/zos/jingyun-zos-agent"

printf '%s\n' "Kylin V10 LVM/XFS and first-boot identity test passed"
