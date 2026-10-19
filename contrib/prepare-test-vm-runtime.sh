#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Prepare the immutable runtime image used as the backing image for test VMs.

set -euo pipefail

# shellcheck source=contrib/test-vm-arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/test-vm-arch.sh"

ROOTFS=
CACHE_DIR=
PACKAGE_FILE=
RUNTIME_KEY=
KEY_OUTPUT=
RUNTIME_DISK_SIZE=${TEST_VM_RUNTIME_DISK_SIZE:-8G}

die() { printf '[test-vm-runtime] error: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
	--rootfs) ROOTFS=$2; shift 2 ;;
	--cache-dir) CACHE_DIR=$2; shift 2 ;;
	--package-file) PACKAGE_FILE=$2; shift 2 ;;
	--runtime-key) RUNTIME_KEY=$2; shift 2 ;;
	--runtime-disk-size) RUNTIME_DISK_SIZE=$2; shift 2 ;;
	--key-output) KEY_OUTPUT=$2; shift 2 ;;
	*) die "unknown argument '$1'" ;;
	esac
done

[[ -s "$ROOTFS" ]] || die "base rootfs is missing: $ROOTFS"
[[ -s "$PACKAGE_FILE" ]] || die "runtime package manifest is missing: $PACKAGE_FILE"
[[ -n "$CACHE_DIR" && -n "$RUNTIME_KEY" && -n "$KEY_OUTPUT" ]] ||
	die "rootfs, cache directory, runtime key, and key output are required"
[[ "$RUNTIME_DISK_SIZE" =~ ^[1-9][0-9]*(K|M|G|T)$ ]] ||
	die "runtime disk size must be a positive QEMU size such as 4G or 512M"

command -v qemu-img >/dev/null 2>&1 ||
	die "qemu-img is required; install it with: $(test_vm_install_cmd "$(test_vm_pkg qemu-utils qemu-img)")"
command -v virt-customize >/dev/null 2>&1 ||
	die "virt-customize is required; install it with: $(test_vm_install_cmd "$(test_vm_pkg libguestfs-tools guestfs-tools)")"

IMAGE="$CACHE_DIR/$RUNTIME_KEY.qcow2"
if [[ -s "$IMAGE" ]]; then
	printf '%s\n' "$RUNTIME_KEY" >"$KEY_OUTPUT"
	exit 0
fi

mkdir -p "$CACHE_DIR" "$(dirname "$KEY_OUTPUT")"
GUESTFS_CACHE_ROOT="${LIBGUESTFS_CACHEDIR:-${TMPDIR:-/tmp}/shirudo-guestfs-cache}"
GUESTFS_CACHE_DIR="$GUESTFS_CACHE_ROOT/${SUPERMIN_KERNEL_VERSION:-host}"
GUESTFS_TMP_DIR="${LIBGUESTFS_TMPDIR:-${TMPDIR:-/tmp}/shirudo-guestfs-tmp}"
GUESTFS_RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}/shirudo-guestfs-run}"
mkdir -p "$GUESTFS_CACHE_DIR"
mkdir -p "$GUESTFS_TMP_DIR"
mkdir -p "$GUESTFS_RUNTIME_DIR"
TMP_IMAGE="$CACHE_DIR/.${RUNTIME_KEY}.tmp.$$"
MARKER="${TMP_IMAGE}.marker"
cleanup() { rm -f -- "$TMP_IMAGE" "$MARKER"; }
trap cleanup EXIT

# The cloud image is intentionally small.  Enlarge the backing overlay and
# grow its existing root partition before installing the runtime packages.
qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$TMP_IMAGE"
qemu-img resize -q "$TMP_IMAGE" "$RUNTIME_DISK_SIZE"
paste -sd, "$PACKAGE_FILE" >"${TMP_IMAGE}.packages"
PACKAGES="$(<"${TMP_IMAGE}.packages")"
rm -f -- "${TMP_IMAGE}.packages"
printf 'shirudo-test-vm-runtime-v1 %s\n' "$RUNTIME_KEY" >"$MARKER"

printf '[test-vm-runtime] preparing %s\n' "$IMAGE" >&2
CUSTOMIZE_LOG="${TMP_IMAGE}.virt-customize.log"
if ! TMPDIR="$GUESTFS_TMP_DIR" XDG_RUNTIME_DIR="$GUESTFS_RUNTIME_DIR" \
	LIBGUESTFS_TMPDIR="$GUESTFS_TMP_DIR" \
	LIBGUESTFS_CACHEDIR="$GUESTFS_CACHE_DIR" virt-customize \
	-a "$TMP_IMAGE" --network --no-selinux-relabel \
	--run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1' \
	--install "$PACKAGES" \
	--upload "$MARKER:/etc/shirudo-test-vm-runtime" \
	--run-command 'apt-get clean' \
	--run-command 'rm -rf /var/lib/apt/lists/*' \
	--run-command 'cloud-init clean --logs --seed' \
	>"$CUSTOMIZE_LOG" 2>&1; then
	printf '[test-vm-runtime] error: could not start or customize the libguestfs appliance\n' >&2
	if grep -q 'no.*kernel\|cannot.*kernel\|vmlinuz.*Permission denied' "$CUSTOMIZE_LOG"; then
		printf '[test-vm-runtime] check: virt-customize needs a readable host vmlinuz; set SUPERMIN_KERNEL or fix /boot permissions\n' >&2
	fi
	if grep -q 'KVM.*disabled\|failed to initialize KVM' "$CUSTOMIZE_LOG"; then
		printf '[test-vm-runtime] check: KVM is unavailable; TCG should work but may be slower\n' >&2
	fi
	if grep -q 'Attempted to kill init\|Kernel panic.*not syncing' "$CUSTOMIZE_LOG"; then
		printf '[test-vm-runtime] check: the selected kernel booted but is not compatible with the libguestfs appliance; use a distribution host kernel via SUPERMIN_KERNEL\n' >&2
	fi
	printf '[test-vm-runtime] last diagnostics:\n' >&2
	tail -20 "$CUSTOMIZE_LOG" >&2
	rm -f -- "$CUSTOMIZE_LOG"
	exit 1
fi
rm -f -- "$CUSTOMIZE_LOG"

mv -- "$TMP_IMAGE" "$IMAGE"
printf '%s\n' "$RUNTIME_KEY" >"$KEY_OUTPUT"
trap - EXIT
rm -f -- "$MARKER"
printf '[test-vm-runtime] ready: %s\n' "$IMAGE" >&2
