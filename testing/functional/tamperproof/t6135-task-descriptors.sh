#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6135 -- a running shirudo's descriptors are not root's to take. Opening
# one through /proc/<pid>/fd and copying one with pidfd_getfd both need
# ptrace access to the task, which the seal refuses for a task the runtime
# image started, counted as SealPtrace; another process's descriptors stay
# reachable as the control. Passing one with SCM_RIGHTS would need shirudo
# to send it, which it never does. Non-destructive.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
PID=
OTHER=
release() {
	[ -n "$PID" ] || return 0
	if [ -d "/proc/$PID" ] &&
		[ "$(awk '{print $3}' "/proc/$PID/stat" 2>/dev/null)" != Z ]; then
		fifo_release "$W/fifo" || true
	fi
	wait "$PID" 2>/dev/null || true
	PID=
}
cleanup() {
	release
	[ -z "$OTHER" ] || kill "$OTHER" 2>/dev/null || true
	rm -rf "$W"
}
trap cleanup EXIT

counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

# The descriptor routes, for pid $1 and descriptor $2: 0 when root got
# the descriptor, 1 when the kernel refused, 3 on anything else.
PROC='
import errno, os, sys
try:
    os.close(os.open("/proc/%s/fd/%s" % (sys.argv[1], sys.argv[2]), os.O_RDONLY))
except OSError as e:
    sys.exit(1 if e.errno in (errno.EACCES, errno.EPERM) else 3)
'
GETFD='
import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
pidfd = libc.syscall(434, int(sys.argv[1]), 0)
if pidfd < 0:
    sys.exit(3)
fd = libc.syscall(438, pidfd, int(sys.argv[2]), 0)
err = ctypes.get_errno()
os.close(pidfd)
if fd >= 0:
    os.close(fd)
    sys.exit(0)
sys.exit(1 if err in (errno.EACCES, errno.EPERM) else 3)
'

before=$(counter SealPtrace) || test_skip_all "no tamper counters"
mkfifo "$W/fifo" || test_skip_all "cannot make a fifo"
"$SHIRUDO_BIN" bpm info "$W/fifo" >/dev/null 2>&1 &
PID=$!
i=0
while [ "$i" -lt 50 ]; do
	[ -d "/proc/$PID" ] || break
	[ "$(awk '{print $3}' "/proc/$PID/stat" 2>/dev/null)" = S ] && break
	sleep 0.1
	i=$((i + 1))
done
[ -d "/proc/$PID" ] || test_skip_all "shirudo did not stay around"
sleep 600 </dev/null &
OTHER=$!

test_expect_success 'another process gives its descriptors up to root' '
	python3 -c "$PROC" "$OTHER" 0 &&
	python3 -c "$GETFD" "$OTHER" 0
'

test_expect_success 'root cannot open a running shirudo descriptor through /proc' '
	for fd in 0 1 2; do
		python3 -c "$PROC" "$PID" "$fd"; [ "$?" = 1 ] || return 1
	done
'

test_expect_success 'nor copy one with pidfd_getfd' '
	for fd in 0 1 2; do
		python3 -c "$GETFD" "$PID" "$fd"; [ "$?" = 1 ] || return 1
	done
'

release

test_expect_success 'every refusal is counted as SealPtrace' '
	[ "$(counter SealPtrace)" -ge $((before + 6)) ]
'

test_done
