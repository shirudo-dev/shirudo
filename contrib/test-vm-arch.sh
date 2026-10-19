# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh disable=SC2034
# Copyright (c) 2026 Authors of shirudo
#
# Host architecture names for the test VM tooling. Sourced by the contrib
# scripts and evaluated by testing/Makefile, so POSIX sh. TEST_VM_ARCH
# overrides the detected architecture. Any other than x86-64 and arm64
# gets the x86-64 names, so that host-side targets still evaluate, and
# TEST_VM_ARCH_SUPPORTED=0, which refuses a kernel build and a boot.

: "${TEST_VM_ARCH:=$(uname -m)}"

TEST_VM_ARCH_SUPPORTED=1
case "$TEST_VM_ARCH" in
x86_64|amd64) TEST_VM_ARCH=x86_64 ;;
aarch64|arm64) TEST_VM_ARCH=aarch64 ;;
*) TEST_VM_ARCH_SUPPORTED=0 ;;
esac

if [ "$TEST_VM_ARCH" = aarch64 ]; then
	TEST_VM_ARCH_KIMAGE=Image
	TEST_VM_ARCH_KIMAGE_SRC=arch/arm64/boot/Image
else
	TEST_VM_ARCH_KIMAGE=bzImage
	TEST_VM_ARCH_KIMAGE_SRC=arch/x86/boot/bzImage
fi
