#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Prepare the immutable runtime image used as the backing image for test VMs.
# --setup-script runs a script in the image after the packages, in the same
# network environment.

set -euo pipefail

# shellcheck source=testing/vm/arch.sh
. "$(dirname "${BASH_SOURCE[0]}")/arch.sh"

ROOTFS=
CACHE_DIR=
PACKAGE_FILE=
SETUP_SCRIPT=
RUNTIME_KEY=
KEY_OUTPUT=
RUNTIME_DISK_SIZE=${TEST_VM_RUNTIME_DISK_SIZE:-8G}

die() { printf '[test-vm-runtime] error: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
	--rootfs) ROOTFS=$2; shift 2 ;;
	--cache-dir) CACHE_DIR=$2; shift 2 ;;
	--package-file) PACKAGE_FILE=$2; shift 2 ;;
	--setup-script) SETUP_SCRIPT=$2; shift 2 ;;
	--runtime-key) RUNTIME_KEY=$2; shift 2 ;;
	--runtime-disk-size) RUNTIME_DISK_SIZE=$2; shift 2 ;;
	--key-output) KEY_OUTPUT=$2; shift 2 ;;
	*) die "unknown argument '$1'" ;;
	esac
done

[[ -s "$ROOTFS" ]] || die "base rootfs is missing: $ROOTFS"
[[ -s "$PACKAGE_FILE" ]] || die "runtime package manifest is missing: $PACKAGE_FILE"
[[ -z "$SETUP_SCRIPT" || -s "$SETUP_SCRIPT" ]] || die "setup script is missing: $SETUP_SCRIPT"
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

# libguestfs defaults to its libvirt backend and to the emulator it was
# built with, usually /usr/libexec/qemu-kvm, and a host with only
# qemu-system-<arch> has neither. Run the appliance directly with the
# emulator the VM uses, unless the caller chose otherwise.
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
if [[ -z "${LIBGUESTFS_HV:-}" ]]; then
	LIBGUESTFS_HV="$(command -v "${TEST_VM_QEMU:-$TEST_VM_ARCH_QEMU}" || true)"
	[[ -z "$LIBGUESTFS_HV" ]] || export LIBGUESTFS_HV
fi

TMP_IMAGE="$CACHE_DIR/.${RUNTIME_KEY}.tmp.$$"
MARKER="${TMP_IMAGE}.marker"
NO_PASST="${TMP_IMAGE}.no-passt"
cleanup() {
	rm -f -- "$TMP_IMAGE" "$MARKER" "${TMP_IMAGE}.nameservers"
	rm -rf -- "$NO_PASST"
}
trap cleanup EXIT

# Started as root, passt changes to nobody before it writes its PID file
# into the directory libguestfs keeps for root, and the appliance never
# starts. libguestfs takes passt to be missing when "passt --help" exits
# with neither 0 nor 1, and then networks the appliance through qemu.
if [[ "$EUID" == 0 ]]; then
	mkdir -p -- "$NO_PASST"
	printf '%s\n' '#!/bin/sh' 'exit 127' >"$NO_PASST/passt"
	chmod +x -- "$NO_PASST/passt"
	PATH="$NO_PASST:$PATH"
fi

# The cloud image is intentionally small.  Enlarge the backing overlay and
# grow its existing root partition before installing the runtime packages.
qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$TMP_IMAGE"
qemu-img resize -q "$TMP_IMAGE" "$RUNTIME_DISK_SIZE"
PACKAGES="$(paste -sd' ' "$PACKAGE_FILE")"
printf 'shirudo-test-vm-runtime-v1 %s\n' "$RUNTIME_KEY" >"$MARKER"

# The appliance gets IPv4 DHCP only, so on a host with IPv6 or stub
# resolvers it has no nameserver. It rebuilds resolv.conf for every command,
# so the host's resolvers are added in the same command as apt rather than
# through virt-customize --install.
NAMESERVERS="${TMP_IMAGE}.nameservers"
awk '$1 == "nameserver" && $2 !~ /^(127\.|::1$|fe80:)/ { print "nameserver " $2 }' \
	"${TEST_VM_RESOLV_CONF:-/etc/resolv.conf}" >"$NAMESERVERS" 2>/dev/null ||
	: >"$NAMESERVERS"
# The appliance does not inherit the caller's proxy; pass it to apt.
# TEST_VM_APT_PROXY overrides http_proxy and https_proxy. The URL goes into
# a shell command, so only a plain one is accepted.
APT_HTTP_PROXY="${TEST_VM_APT_PROXY:-${http_proxy:-${HTTP_PROXY:-}}}"
APT_HTTPS_PROXY="${TEST_VM_APT_PROXY:-${https_proxy:-${HTTPS_PROXY:-$APT_HTTP_PROXY}}}"
PROXY_OPTS=""
for proxy_url in "$APT_HTTP_PROXY" "$APT_HTTPS_PROXY"; do
	[[ -z "$proxy_url" || "$proxy_url" =~ ^https?://[]A-Za-z0-9._:@%/[-]+$ ]] ||
		die "the apt proxy must be a plain http:// or https:// URL"
done
[[ -z "$APT_HTTP_PROXY" ]] ||
	PROXY_OPTS+=" -o Acquire::http::Proxy=$APT_HTTP_PROXY"
[[ -z "$APT_HTTPS_PROXY" ]] ||
	PROXY_OPTS+=" -o Acquire::https::Proxy=$APT_HTTPS_PROXY"
# A setup script runs apt and curl itself, which take the proxy from the
# environment.
SETUP_COMMAND=
SETUP_ARGS=()
if [[ -n "$SETUP_SCRIPT" ]]; then
	SETUP_COMMAND="env${APT_HTTP_PROXY:+ http_proxy=$APT_HTTP_PROXY}${APT_HTTPS_PROXY:+ https_proxy=$APT_HTTPS_PROXY} sh /root/shirudo-setup"
	SETUP_ARGS=(--upload "$SETUP_SCRIPT:/root/shirudo-setup")
fi
# shellcheck disable=SC2016 # expanded in the appliance
INSTALL_SCRIPT='set -e
export DEBIAN_FRONTEND=noninteractive
if ! grep -q "^nameserver" /etc/resolv.conf; then
	cat /root/shirudo-nameservers >>/etc/resolv.conf
fi
apt_opts="-q -y -o Dpkg::Options::=--force-confnew'"$PROXY_OPTS"'"
apt-get $apt_opts update
apt-get $apt_opts install '"$PACKAGES"'
'"$SETUP_COMMAND"

printf '[test-vm-runtime] preparing %s\n' "$IMAGE" >&2
CUSTOMIZE_LOG="${TMP_IMAGE}.virt-customize.log"
if ! TMPDIR="$GUESTFS_TMP_DIR" XDG_RUNTIME_DIR="$GUESTFS_RUNTIME_DIR" \
	LIBGUESTFS_TMPDIR="$GUESTFS_TMP_DIR" \
	LIBGUESTFS_CACHEDIR="$GUESTFS_CACHE_DIR" virt-customize \
	-a "$TMP_IMAGE" --network --no-selinux-relabel \
	--run-command 'growpart /dev/sda 1 && resize2fs /dev/sda1' \
	--upload "$NAMESERVERS:/root/shirudo-nameservers" \
	"${SETUP_ARGS[@]}" \
	--run-command "$INSTALL_SCRIPT" \
	--run-command 'rm -f /root/shirudo-nameservers /root/shirudo-setup' \
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
	if grep -q '^\(Err\|W\):' "$CUSTOMIZE_LOG"; then
		printf '[test-vm-runtime] apt could not fetch:\n' >&2
		grep -A1 '^\(Err\|W\):' "$CUSTOMIZE_LOG" | head -40 >&2
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
rm -rf -- "$NO_PASST"
printf '[test-vm-runtime] ready: %s\n' "$IMAGE" >&2
