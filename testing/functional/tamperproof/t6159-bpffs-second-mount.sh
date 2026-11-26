#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6159 -- a second mount of the private bpffs is a second name for the
# same pins and no other way to them. A legacy mount(2) with MS_BIND
# names its source in a string lsm/sb_mount cannot resolve, so root can
# bind the bpffs somewhere else. The guards go by the file system and
# not by the path: through the second mount a pin is no more unlinked,
# renamed or opened than through the first, and the second mount is no
# more unmounted, remounted or mounted over than the first.
#
# Each call is made in a mount namespace of its own, which takes the
# second mount with it when the caller exits: the guards refuse the
# unmount, so nothing else would remove it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
C=helper/test-bpf-cmd
[ -x "$C" ] || test_skip_all "test-bpf-cmd helper not built"
B=/run/shirudo/bpffs
mountpoint -q "$B" || test_skip_all "no private bpffs"

W=$(mktemp -d)
M=$W/second.py
COPY=$W/copy
mkdir "$COPY"
trap 'rm -rf "$W"' EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

enforcing() {
	mountpoint -q "$B" && test -e "$B/lsm_link" &&
		[ "$(./$C LINK_CREATE)" = "errno=13" ]
}

# In a new mount namespace, bind the bpffs at the second path with the
# legacy call, make one call there and answer with 0 or the name of its
# errno. A pin is named relative to the second mount.
cat >"$M" <<'PY'
import ctypes as c
import errno
import os
import sys

libc = c.CDLL(None, use_errno=True)
libc.syscall.restype = c.c_long
bpffs, copy, op = (os.fsencode(a) for a in sys.argv[1:4])
names = [os.path.join(copy, os.fsencode(a)) for a in sys.argv[4:]]


def failed(what):
    sys.exit("%s: %s" % (what, errno.errorcode[c.get_errno()]))


# CLONE_NEWNS, then MS_REC | MS_PRIVATE on / and MS_BIND.
if libc.unshare(0x20000):
    failed("unshare")
if libc.mount(None, b"/", None, c.c_ulong(1 << 14 | 1 << 18), None):
    failed("private")
if libc.mount(bpffs, copy, None, c.c_ulong(1 << 12), None):
    failed("bind")

if op == b"stat":
    ret = 0 if os.path.lexists(names[0]) else -1
    c.set_errno(errno.ENOENT)
elif op == b"unlink":
    ret = libc.unlink(names[0])
elif op == b"rename":
    ret = libc.rename(names[0], names[1])
elif op == b"obj-get":
    # union bpf_attr for BPF_OBJ_GET: pathname, bpf_fd, file_flags.
    path = c.create_string_buffer(names[0])
    attr = (c.c_uint64 * 2)(c.addressof(path), 0)
    nr = {"x86_64": 321, "aarch64": 280}[os.uname().machine]
    ret = libc.syscall(nr, 7, c.byref(attr), c.c_uint(c.sizeof(attr)))
    ret = 0 if ret >= 0 else -1
elif op == b"umount":
    ret = libc.umount2(copy, 0)
elif op == b"detach":
    # MNT_DETACH
    ret = libc.umount2(copy, 2)
elif op == b"remount":
    # MS_REMOUNT | MS_RDONLY
    ret = libc.mount(None, copy, None, c.c_ulong(1 << 5 | 1), None)
elif op == b"over":
    ret = libc.mount(b"none", copy, b"tmpfs", c.c_ulong(0), None)
else:
    sys.exit(2)
print(0 if ret == 0 else errno.errorcode[c.get_errno()])
PY

second() {
	python3 "$M" "$B" "$COPY" "$@"
}

test_expect_success 'enforcement is live to begin with' '
	enforcing
'

test_expect_success 'a legacy bind gives the bpffs a second mount point' '
	[ "$(second stat lsm_link)" = 0 ] &&
	[ "$(second stat no-such-pin)" = ENOENT ]
'

test_expect_success 'a pin is not unlinked through it, and the attempt is counted' '
	before=$(counter PinUnlink) &&
	[ "$(second unlink lsm_link)" = EPERM ] &&
	[ "$(counter PinUnlink)" -gt "$before" ] &&
	enforcing
'

test_expect_success 'nor renamed' '
	before=$(counter PinRename) &&
	[ "$(second rename lsm_link moved)" = EPERM ] &&
	[ "$(counter PinRename)" -gt "$before" ] &&
	test ! -e "$B/moved" &&
	enforcing
'

test_expect_success 'nor opened' '
	before=$(counter ObjGet) &&
	[ "$(second obj-get lsm_link)" = EACCES ] &&
	[ "$(counter ObjGet)" -gt "$before" ]
'

test_expect_success 'the second mount is not unmounted either' '
	before=$(counter BpffsUmount) &&
	[ "$(second umount)" = EPERM ] &&
	[ "$(second detach)" = EPERM ] &&
	[ "$(counter BpffsUmount)" -ge "$((before + 2))" ] &&
	enforcing
'

test_expect_success 'nor remounted or mounted over' '
	before=$(counter BpffsMount) &&
	[ "$(second remount)" = EPERM ] &&
	[ "$(second over)" = EPERM ] &&
	[ "$(counter BpffsMount)" -gt "$before" ] &&
	enforcing
'

test_expect_success 'none of it reached the namespace of init' '
	! mountpoint -q "$COPY" &&
	[ "$(findmnt -n -t bpf -o TARGET | grep -c "^$B\$")" = 1 ] &&
	enforcing
'

test_done
