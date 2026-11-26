#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6158 -- root detached the private bpffs with no hook and no counter by
# first making the mount tree private, so the kernel would let a legacy
# MS_MOVE relocate the bpffs (do_move_mount refuses a move whose parent
# is shared), then moving it onto a procfs dentry the kernel later
# invalidates through the hookless __detach_mounts path. The LSM cannot
# see a legacy MS_MOVE's source, so the fix guards the precondition: the
# sb_mount hook refuses a propagation change by a task without authority
# on the bpffs mount or any ancestor (BpffsMount), keeping the ancestry
# shared so the kernel keeps refusing the move, and the sb_pivotroot hook
# refuses a pivot_root by such a task in the bpffs's own mount namespace
# (BpffsUmountAbove). A change in a mount namespace of its own is any
# process's to make and enforcement stays.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
C=helper/test-bpf-cmd
[ -x "$C" ] || test_skip_all "test-bpf-cmd helper not built"
B=/run/shirudo/bpffs
W=/tmp/t6158
HOLDER=

# The guarded changes must all be refused, so the real mount tree is
# never altered. Restore shared propagation anyway, in case a regression
# let a partial change through before the hook refused the rest.
cleanup() {
	[ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
	umount -l "$W" 2>/dev/null || true
	rm -rf "$W" 2>/dev/null || true
	mount --make-rshared / 2>/dev/null || true
}
trap cleanup EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

enforcing() {
	mountpoint -q "$B" && [ "$(./$C LINK_CREATE)" = "errno=13" ]
}

test_expect_success 'enforcement is live to begin with' '
	enforcing
'

# The reproduction needs the bpffs parent non-shared. A recursive
# make-private from / is one sb_mount call on the root mount, which the
# old guard let through because the hook path sb was not the bpffs tmpfs.
test_expect_success 'a recursive make-private of / is refused and counted' '
	before=$(counter BpffsMount) &&
	! mount --make-rprivate / 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsMount)" -gt "$before" ]
'

# Making the bpffs parent itself private is the same precondition by a
# shorter path; also refused, also counted.
test_expect_success 'making the bpffs parent private is refused and counted' '
	before=$(counter BpffsMount) &&
	! mount --make-private /run 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsMount)" -gt "$before" ]
'

# With the ancestry still shared, the kernel refuses the MS_MOVE itself
# (do_move_mount: parent is shared), so the bpffs is never relocated.
test_expect_success 'a legacy MS_MOVE of the bpffs stays refused by the kernel' '
	sleep 300 &
	HOLDER=$! &&
	! mount --move "$B" /proc/$HOLDER/task 2>/dev/null &&
	mountpoint -q "$B" &&
	enforcing &&
	kill "$HOLDER" 2>/dev/null; HOLDER=
'

# pivot_root relocates the namespace root and so could strand the bpffs;
# its old root is not passed to the hook, so a pivot by a task without
# authority in the bpffs namespace is refused.
test_expect_success 'pivot_root in the bpffs mount namespace is refused and counted' '
	before=$(counter BpffsUmountAbove) &&
	mkdir -p "$W/put" &&
	mount --bind "$W" "$W" &&
	! pivot_root "$W" "$W/put" 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsUmountAbove)" -gt "$before" ] &&
	umount -l "$W" 2>/dev/null; rm -rf "$W"
'

# The guards are scoped to init's own mount objects. A mount namespace of
# its own holds copies, so the same propagation change is any process's
# to make there and enforcement is untouched.
test_expect_success 'the same change in a private mount namespace is harmless' '
	unshare -m --propagation private sh -c "mount --make-rprivate /" &&
	enforcing
'

test_done
