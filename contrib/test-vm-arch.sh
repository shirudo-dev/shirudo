# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh disable=SC2034
# Copyright (c) 2026 Authors of shirudo
#
# Host architecture and package manager for the test VM tooling. Sourced
# by the contrib scripts and evaluated by testing/Makefile, so POSIX sh.
# TEST_VM_ARCH and TEST_VM_HOST_PKG override the detection. An
# architecture other than x86-64 and arm64 gets the x86-64 names, so that
# host-side targets still evaluate, and TEST_VM_ARCH_SUPPORTED=0, which
# refuses a kernel build and a boot.

: "${TEST_VM_ARCH:=$(uname -m)}"

TEST_VM_ARCH_SUPPORTED=1
case "$TEST_VM_ARCH" in
x86_64|amd64) TEST_VM_ARCH=x86_64 ;;
aarch64|arm64) TEST_VM_ARCH=aarch64 ;;
*) TEST_VM_ARCH_SUPPORTED=0 ;;
esac

if [ "$TEST_VM_ARCH" = aarch64 ]; then
	TEST_VM_ARCH_QEMU=qemu-system-aarch64
	TEST_VM_ARCH_QEMU_DEB=qemu-system-arm
	TEST_VM_ARCH_QEMU_RPM=qemu-system-aarch64-core
	TEST_VM_ARCH_CONSOLE=ttyAMA0
	TEST_VM_ARCH_KIMAGE=Image
	TEST_VM_ARCH_KIMAGE_SRC=arch/arm64/boot/Image
	TEST_VM_ARCH_DEB=arm64
	TEST_VM_ARCH_MIRROR=https://ports.ubuntu.com/ubuntu-ports
else
	TEST_VM_ARCH_QEMU=qemu-system-x86_64
	TEST_VM_ARCH_QEMU_DEB=qemu-system-x86
	TEST_VM_ARCH_QEMU_RPM=qemu-system-x86-core
	TEST_VM_ARCH_CONSOLE=ttyS0
	TEST_VM_ARCH_KIMAGE=bzImage
	TEST_VM_ARCH_KIMAGE_SRC=arch/x86/boot/bzImage
	TEST_VM_ARCH_DEB=amd64
	TEST_VM_ARCH_MIRROR=https://archive.ubuntu.com/ubuntu
fi

# dnf on Fedora, RHEL and their derivatives as os-release names them, apt
# anywhere else.
if [ -z "${TEST_VM_HOST_PKG:-}" ]; then
	TEST_VM_HOST_PKG=apt
	if [ -r /etc/os-release ]; then
		case " $(. /etc/os-release; echo "${ID:-} ${ID_LIKE:-}") " in
		*" fedora "*|*" rhel "*|*" centos "*) TEST_VM_HOST_PKG=dnf ;;
		esac
	fi
fi
if [ "$TEST_VM_HOST_PKG" = dnf ]; then
	TEST_VM_HOST_PKG_FORMAT=rpm
else
	TEST_VM_HOST_PKG=apt
	TEST_VM_HOST_PKG_FORMAT=deb
fi

# test_vm_pkg DEB RPM: the name of the package on this host.
test_vm_pkg()
{
	if [ "$TEST_VM_HOST_PKG" = dnf ]; then
		printf '%s\n' "$2"
	else
		printf '%s\n' "$1"
	fi
}

# test_vm_install_cmd PACKAGE...: the command that installs them here.
test_vm_install_cmd()
{
	if [ "$TEST_VM_HOST_PKG" = dnf ]; then
		printf 'sudo dnf install -y'
	else
		printf 'sudo apt-get install -y --no-install-recommends'
	fi
	printf ' %s' "$@"
	printf '\n'
}
