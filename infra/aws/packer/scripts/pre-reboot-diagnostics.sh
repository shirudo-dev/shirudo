#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -uo pipefail

section() {
  printf '\n===== %s =====\n' "$1"
}

run() {
  printf '+ %s\n' "$*"
  "$@" 2>&1 || printf 'command failed with exit %s: %s\n' "$?" "$*"
}

run_shell() {
  printf '+ %s\n' "$*"
  bash -c "$*" 2>&1 || printf 'command failed with exit %s: %s\n' "$?" "$*"
}

expected_kernel=""
if [[ -r /etc/bpf-next-kernel-release ]]; then
  expected_kernel="$(cat /etc/bpf-next-kernel-release)"
fi

section "Kernel Metadata"
run uname -a
run cat /etc/os-release
if [[ -n "$expected_kernel" ]]; then
  printf 'expected_kernel=%s\n' "$expected_kernel"
else
  printf 'expected_kernel=<missing /etc/bpf-next-kernel-release>\n'
fi
if [[ -r /etc/bpf-next-kernel-build ]]; then
  run cat /etc/bpf-next-kernel-build
fi

section "Boot Files"
run ls -lh /boot
if [[ -n "$expected_kernel" ]]; then
  run ls -lh "/boot/vmlinuz-${expected_kernel}" "/boot/initrd.img-${expected_kernel}" "/boot/config-${expected_kernel}"
fi

section "Installed Kernel Packages"
run_shell "dpkg -l 'linux-image*' 'linux-headers*' 'linux-libc-dev*' 2>/dev/null | sed -n '1,160p'"

section "GRUB Defaults"
if [[ -r /etc/default/grub ]]; then
  run sed -n '1,220p' /etc/default/grub
fi
for grub_default in /etc/default/grub.d/*.cfg; do
  [[ -e "$grub_default" ]] || continue
  printf '\n--- %s ---\n' "$grub_default"
  sed -n '1,220p' "$grub_default" 2>&1 || true
done

section "GRUB Entries For Expected Kernel"
if [[ -n "$expected_kernel" && -r /boot/grub/grub.cfg ]]; then
  printf '+ grep -F -n -A 12 -B 3 %q /boot/grub/grub.cfg\n' "$expected_kernel"
  grep -F -n -A 12 -B 3 "$expected_kernel" /boot/grub/grub.cfg 2>&1 |
    sed -n '1,240p' || true
elif [[ ! -r /boot/grub/grub.cfg ]]; then
  printf '/boot/grub/grub.cfg is not readable\n'
  run ls -lh /boot/grub
fi

section "GRUB linux/initrd Lines"
if [[ -r /boot/grub/grub.cfg ]]; then
  run_shell "grep -nE '^[[:space:]]*(menuentry|linux|linuxefi|initrd|initrdefi)[[:space:]]' /boot/grub/grub.cfg | sed -n '1,240p'"
fi

section "Expected Kernel Config"
if [[ -n "$expected_kernel" && -r "/boot/config-${expected_kernel}" ]]; then
  for symbol in \
    CONFIG_BPF_LSM \
    CONFIG_DEBUG_INFO_BTF \
    CONFIG_PCI \
    CONFIG_PCI_MSI \
    CONFIG_NETDEVICES \
    CONFIG_ETHERNET \
    CONFIG_NET_VENDOR_AMAZON \
    CONFIG_ENA_ETHERNET \
    CONFIG_NVME_CORE \
    CONFIG_BLK_DEV_NVME \
    CONFIG_NVME_MULTIPATH \
    CONFIG_DEVTMPFS \
    CONFIG_TCG_TPM \
    CONFIG_TCG_TIS_CORE \
    CONFIG_TCG_TIS \
    CONFIG_TCG_CRB \
    CONFIG_BLK_DEV_LOOP \
    CONFIG_SQUASHFS \
    CONFIG_EXT4_FS \
    CONFIG_XFS_FS; do
    grep -E "^${symbol}=|^# ${symbol} is not set" "/boot/config-${expected_kernel}" || true
  done
fi

section "Expected Initramfs Driver Hints"
if [[ -n "$expected_kernel" && -r "/boot/initrd.img-${expected_kernel}" ]]; then
  if command -v lsinitramfs >/dev/null 2>&1; then
    printf '+ lsinitramfs /boot/initrd.img-%s | grep -E "(^|/)(ena|nvme|ext4|xfs|virtio)[^/]*$"\n' "$expected_kernel"
    lsinitramfs "/boot/initrd.img-${expected_kernel}" 2>&1 |
      grep -E '(^|/)(ena|nvme|ext4|xfs|virtio)[^/]*$' |
      sed -n '1,200p' || true
  else
    printf 'lsinitramfs is not installed\n'
  fi
fi

section "Current Root And Network"
run findmnt /
run lsblk -f
run ip addr
run ip route

section "SSM Agent State"
run_shell "systemctl --no-pager status amazon-ssm-agent snap.amazon-ssm-agent.amazon-ssm-agent 2>&1 | sed -n '1,180p'"
