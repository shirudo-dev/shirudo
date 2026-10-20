#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

state=${SHIRUDO_VERITY_VM_STATE:-$HOME/.linux-kernel-vscode/shirudo-verity}
key=${SHIRUDO_VERITY_VM_SSH_KEY:-$HOME/.ssh/linux-kernel-vscode-rsa}
port=${SHIRUDO_VERITY_VM_PORT:-5557}
gdb_port=${SHIRUDO_VERITY_VM_GDB_PORT:-1236}
command=${1:-help}
shift || true
ssh_args=(-p "$port" -i "$key" -o IdentitiesOnly=yes -o BatchMode=yes
	-o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new
	-o UserKnownHostsFile="$state/known_hosts")

case "$command" in
ssh)
	exec ssh "${ssh_args[@]}" root@127.0.0.1 "$@"
	;;
push)
	[ $# -eq 2 ] || exit 2
	exec scp -O -P "$port" -i "$key" -o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$state/known_hosts" \
		"$1" "root@127.0.0.1:$2"
	;;
pull)
	[ $# -eq 2 ] || exit 2
	exec scp -O -P "$port" -i "$key" -o IdentitiesOnly=yes \
		-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$state/known_hosts" \
		"root@127.0.0.1:$1" "$2"
	;;
stop)
	exec ssh -n "${ssh_args[@]}" root@127.0.0.1 poweroff
	;;
start|start-install)
	[ -f "$state/debian-x86_64.img" ] || { echo "missing cloned rootfs in $state" >&2; exit 1; }
	;;
*)
	printf 'usage: %s start-install|start|stop|ssh|push|pull [arguments]\n' "$0"
	exit 2
	;;
esac

exec 9>"$state/vm.lock"
flock -n 9 || { echo 'prototype VM is already running' >&2; exit 1; }
mkdir -p "$state/tpm"
rm -f "$state/tpm.sock"
swtpm socket --tpm2 --tpmstate dir="$state/tpm" \
	--ctrl type=unixio,path="$state/tpm.sock" \
	--flags not-need-init,startup-clear &
tpm_pid=$!
trap 'kill "$tpm_pid" 2>/dev/null || true; wait "$tpm_pid" 2>/dev/null || true' EXIT
for ((attempt = 0; attempt < 50; attempt++)); do
	[[ -S "$state/tpm.sock" ]] && break
	kill -0 "$tpm_pid"
	sleep 0.1
done
[[ -S "$state/tpm.sock" ]]

if [[ "$command" == start-install ]]; then
	boot=(-kernel "$state/vmlinuz-bootstrap" -initrd "$state/initrd-bootstrap.img"
		-append 'console=ttyS0,115200 root=/dev/vda rw nokaslr lsm=bpf bpf.keyring_unsealed=1 rd.systemd.mask=shirudo-initrd.service systemd.mask=shirudo.service')
else
	[ -f "$state/verity-ready" ] || { echo 'install and verify the prototype UKI first' >&2; exit 1; }
	boot=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
		-drive if=pflash,format=raw,file="$state/OVMF_VARS_4M.fd"
		-drive if=virtio,format=raw,readonly=on,file="$state/esp.img")
fi
qemu-system-x86_64 -enable-kvm -cpu host -machine q35 -name shirudo-verity \
	-smp 4 -m 4G -display none -monitor none -serial stdio \
	-gdb tcp:127.0.0.1:"$gdb_port" \
	-qmp unix:"$state/qmp.sock",server=on,wait=off \
	-netdev user,id=net0,hostfwd=tcp:127.0.0.1:"$port"-:22 \
	-device virtio-net-pci,netdev=net0 \
	-drive file="$state/debian-x86_64.img",format=raw,if=virtio \
	-chardev socket,id=chrtpm,path="$state/tpm.sock" \
	-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
	"${boot[@]}" "$@"
