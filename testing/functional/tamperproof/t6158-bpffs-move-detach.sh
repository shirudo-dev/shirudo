#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6158 -- root detached the private bpffs with no hook and no counter by
# first making the mount tree private, so the kernel would let a legacy
# MS_MOVE relocate the bpffs (do_move_mount refuses a move whose parent
# is shared), then moving it onto a procfs dentry the kernel later
# invalidates through the hookless __detach_mounts path. The LSM cannot
# see a legacy MS_MOVE's source, and mount_setattr(2) changes propagation
# with no hook, so the guards refuse the move itself: every legacy
# MS_MOVE in the bpffs's mount namespace, and a move_mount(2) of the
# bpffs or of a mount above it (BpffsMount). A propagation change on the
# bpffs or a mount above it through mount(2), which lsm/sb_mount sees, is
# refused as well (BpffsMount), and a pivot_root in that namespace
# (BpffsUmountAbove). A mount namespace of its own is any process's to
# change and enforcement stays.
#
# Each move is tried with the parent made private first, through
# mount_setattr(2), which is the state the bypass needs, and the move
# has to be refused all the same. The calls are made with the syscalls
# themselves, so that no util-linux picks another one.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
command -v pivot_root >/dev/null 2>&1 || test_skip_all "no pivot_root"
C=helper/test-bpf-cmd
[ -x "$C" ] || test_skip_all "test-bpf-cmd helper not built"
B=/run/shirudo/bpffs
W=/tmp/t6158
M=/tmp/t6158-mnt.py
HOLDER=

mountpoint -q "$B" || test_skip_all "no private bpffs"

# The guarded changes must all be refused, so the real mount tree is
# never altered. Restore shared propagation anyway, in case a regression
# let a partial change through before the hook refused the rest.
cleanup() {
	[ -n "$HOLDER" ] && kill "$HOLDER" 2>/dev/null
	umount -l "$W" 2>/dev/null || true
	rm -rf "$W" "$M" 2>/dev/null || true
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

# One mount call, answered with 0 or the name of its errno.
cat >"$M" <<'PY'
import ctypes as c
import errno
import os
import sys

libc = c.CDLL(None, use_errno=True)
op, args = sys.argv[1], [os.fsencode(a) for a in sys.argv[2:]]
if op == "legacy-move":
    # MS_MOVE
    ret = libc.mount(args[0], args[1], None, c.c_ulong(1 << 13), None)
elif op == "move-mount":
    # AT_FDCWD on both sides, no flags.
    ret = libc.move_mount(-100, args[0], -100, args[1], 0)
elif op == "setattr-private":
    # struct mount_attr: attr_set, attr_clr, propagation, userns_fd.
    attr = (c.c_uint64 * 4)(0, 0, 1 << 18, 0)
    ret = libc.mount_setattr(-100, args[0], 0, c.byref(attr),
                             c.c_size_t(c.sizeof(attr)))
else:
    sys.exit(2)
print(0 if ret == 0 else errno.errorcode[c.get_errno()])
PY

mnt_try() {
	python3 "$M" "$@"
}

test_expect_success 'enforcement is live to begin with' '
	enforcing
'

# The reproduction needs the bpffs parent non-shared. A recursive
# make-private from / is one propagation change on the root mount. Force
# the legacy mount(2) path so the assertion is deterministic regardless
# of the host util-linux; it reaches lsm/sb_mount, which the old guard
# let through because the hook-path superblock was not the bpffs tmpfs.
test_expect_success 'a forced legacy recursive make-private of / is refused and counted' '
	before=$(counter BpffsMount) &&
	! LIBMOUNT_FORCE_MOUNT2=always mount --make-rprivate / 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsMount)" -gt "$before" ]
'

# Making the bpffs parent itself private is the same precondition by a
# shorter path; also refused, also counted, over the forced legacy path.
test_expect_success 'a forced legacy make-private of /run is refused and counted' '
	before=$(counter BpffsMount) &&
	! LIBMOUNT_FORCE_MOUNT2=always mount --make-private /run 2>/dev/null &&
	enforcing &&
	[ "$(counter BpffsMount)" -gt "$before" ]
'

# The bypass itself: /run private, then the bpffs moved onto a procfs
# entry that goes away with its task. The kernel alone answers EINVAL
# while /run is shared, so EPERM is the guard's, on either kernel. /run
# is shared again before anything is asserted.
test_expect_success 'the bpffs does not move from a private /run, by either call' '
	sleep 300 &
	HOLDER=$!
	before=$(counter BpffsMount)
	mnt_try setattr-private /run >/dev/null
	legacy=$(mnt_try legacy-move "$B" /proc/$HOLDER/task)
	new=$(mnt_try move-mount "$B" /proc/$HOLDER/task)
	mount --make-shared /run
	kill "$HOLDER" 2>/dev/null
	HOLDER=
	[ "$legacy" = EPERM ] && [ "$new" = EPERM ] &&
	mountpoint -q "$B" &&
	enforcing &&
	[ "$(counter BpffsMount)" -ge "$((before + 2))" ]
'

# One level up: with / private, /run would move with the bpffs in it.
test_expect_success '/run does not move from a private /, by either call' '
	sleep 300 &
	HOLDER=$!
	before=$(counter BpffsMount)
	mnt_try setattr-private / >/dev/null
	legacy=$(mnt_try legacy-move /run /proc/$HOLDER/task)
	new=$(mnt_try move-mount /run /proc/$HOLDER/task)
	mount --make-shared /
	kill "$HOLDER" 2>/dev/null
	HOLDER=
	[ "$legacy" = EPERM ] && [ "$new" = EPERM ] &&
	mountpoint -q "$B" &&
	enforcing &&
	[ "$(counter BpffsMount)" -ge "$((before + 2))" ]
'

# The legacy call names no source to the hook, so it is refused for
# every mount of this namespace; move_mount(2) is not, and gets the
# kernel's own answer for a mount that has nothing to do with the bpffs.
test_expect_success 'a legacy MS_MOVE of an unrelated mount is refused, move_mount is not' '
	mkdir -p "$W/a" "$W/b" &&
	mount --bind "$W/a" "$W/a" &&
	legacy=$(mnt_try legacy-move "$W/a" "$W/b") &&
	new=$(mnt_try move-mount "$W/a" "$W/b")
	umount -l "$W/b" 2>/dev/null
	umount -l "$W/a" 2>/dev/null
	rm -rf "$W"
	[ "$legacy" = EPERM ] && [ -n "$new" ] && [ "$new" != EPERM ]
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
	[ "$(counter BpffsUmountAbove)" -gt "$before" ]
	pivot=$?
	umount -l "$W" 2>/dev/null
	rm -rf "$W"
	[ "$pivot" = 0 ]
'

# The guards are scoped to init's own mount objects. A mount namespace of
# its own holds copies, so the same propagation change and a legacy move
# are any process's to make there and enforcement is untouched.
test_expect_success 'the same changes in a private mount namespace are harmless' '
	mkdir -p "$W/a" "$W/b" &&
	unshare -m --propagation private sh -c "
		mount --make-rprivate / &&
		mount --bind $W/a $W/a &&
		[ \"\$(python3 $M legacy-move $W/a $W/b)\" = 0 ]
	" &&
	enforcing
'

test_done
