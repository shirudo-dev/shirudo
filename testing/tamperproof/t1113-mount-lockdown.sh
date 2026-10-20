#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1113 -- mount-lifecycle lockdown of the private bpffs. shirudo is
# agentless, so once init exits the pinned LSM links are kept alive only
# by the bpffs pins; tearing the superblock down detaches all
# enforcement. bpf2's sb_umount/move_mount/sb_mount/sb_remount hooks deny
# the whole mount lifecycle of that superblock, so a plain (or lazy)
# `umount` of /run/shirudo/bpffs -- which before these hooks silently
# disabled every LSM program -- is refused, and enforcement survives.
#
# Non-destructive when the guards work (the operations are denied, so
# nothing changes). If a guard has regressed and the bpffs actually gets
# unmounted, the trap re-inits to restore the host rather than leave it
# unprotected.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

H=helper/test-bpf-load
[ -x "$H" ] || test_skip_all "test-bpf-load helper not built"
B=/run/shirudo/bpffs
mountpoint -q "$B" 2>/dev/null || test_skip_all "bpffs not mounted at $B"

restore() {
	# Only fires if a guard regressed and the bpffs came unmounted.
	mountpoint -q "$B" 2>/dev/null ||
		"$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

# Sanity: enforcement is live before we start (unsigned load -> EACCES).
test_expect_success 'baseline: unsigned userspace load is denied' '
	[ "$(./$H)" = "errno=13" ]
'

test_expect_success 'umount of the bpffs is denied and enforcement survives' '
	umount "$B" 2>/dev/null
	mountpoint -q "$B" &&
	[ "$(./$H)" = "errno=13" ]
'

test_expect_success 'lazy umount (MNT_DETACH) of the bpffs is denied' '
	umount -l "$B" 2>/dev/null
	mountpoint -q "$B" &&
	[ "$(./$H)" = "errno=13" ]
'

test_expect_success 'remount of the bpffs is denied' '
	mount -o remount,rw "$B" 2>/dev/null
	mountpoint -q "$B" &&
	[ "$(./$H)" = "errno=13" ]
'

test_expect_success 'mounting over the bpffs is denied' '
	mount -t tmpfs none "$B" 2>/dev/null
	# A successful shadow-mount would leave a tmpfs (not bpf) on top.
	[ "$(findmnt -no FSTYPE "$B" | head -1)" = "bpf" ] &&
	[ "$(./$H)" = "errno=13" ]
'

test_done
