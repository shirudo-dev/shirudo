# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=bash
# Copyright (c) 2026 Authors of shirudo
#
# The libguestfs appliance the scripts that read or change a runtime image
# run: guestfs_setup once, then each libguestfs tool through guestfs_run.
# Sourced after arch.sh.

guestfs_setup()
{
	local cache_root="${LIBGUESTFS_CACHEDIR:-${TMPDIR:-/tmp}/shirudo-guestfs-cache}"

	GUESTFS_CACHE_DIR="$cache_root/${SUPERMIN_KERNEL_VERSION:-host}"
	GUESTFS_TMP_DIR="${LIBGUESTFS_TMPDIR:-${TMPDIR:-/tmp}/shirudo-guestfs-tmp}"
	GUESTFS_RUNTIME_DIR="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}/shirudo-guestfs-run}"
	mkdir -p "$GUESTFS_CACHE_DIR" "$GUESTFS_TMP_DIR" "$GUESTFS_RUNTIME_DIR"

	# libguestfs defaults to its libvirt backend and to the emulator it
	# was built with, usually /usr/libexec/qemu-kvm, and a host with only
	# qemu-system-<arch> has neither. Run the appliance directly with the
	# emulator the VM uses, unless the caller chose otherwise.
	export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
	if [[ -z "${LIBGUESTFS_HV:-}" ]]; then
		LIBGUESTFS_HV="$(command -v "${TEST_VM_QEMU:-$TEST_VM_ARCH_QEMU}" || true)"
		[[ -z "$LIBGUESTFS_HV" ]] || export LIBGUESTFS_HV
	fi
}

guestfs_run()
{
	TMPDIR="$GUESTFS_TMP_DIR" XDG_RUNTIME_DIR="$GUESTFS_RUNTIME_DIR" \
		LIBGUESTFS_TMPDIR="$GUESTFS_TMP_DIR" \
		LIBGUESTFS_CACHEDIR="$GUESTFS_CACHE_DIR" "$@"
}
