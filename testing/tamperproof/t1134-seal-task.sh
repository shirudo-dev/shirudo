#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1134 -- the seal's task hooks (bpf/seal.c ptrace_access_check and
# perf_event_alloc): a task that runs the labelled shirudo binary can
# neither be ptrace-attached nor have a perf event bound to it, even by
# root. The task is a shirudo blocked on opening a fifo, released at
# the end. Non-destructive.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -e /run/shirudo/bpffs/seal_ptrace_access_check_link ] ||
	test_skip_all "the seal's task hooks are not attached on this target"

W=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
PID=
cleanup() {
	# A writer lets the blocked open return; shirudo then rejects the
	# input and exits. ENXIO means it is not waiting any more.
	[ -n "$PID" ] && python3 -c '
import os, sys
try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
    os.write(fd, b"x")
    os.close(fd)
except OSError:
    pass' "$W/fifo" 2>/dev/null
	if [ -n "$PID" ]; then
		wait "$PID" 2>/dev/null || :
	fi
	rm -rf "$W"
}
trap cleanup EXIT

mkfifo "$W/fifo" || test_skip_all "cannot make a fifo"
"$SHIRUDO_BIN" bpm info "$W/fifo" >/dev/null 2>&1 &
PID=$!
# Blocked in open(2) of the fifo: alive and sleeping.
i=0
while [ "$i" -lt 50 ]; do
	[ -d "/proc/$PID" ] || break
	[ "$(awk '{print $3}' "/proc/$PID/stat" 2>/dev/null)" = S ] && break
	sleep 0.1
	i=$((i + 1))
done
[ -d "/proc/$PID" ] || test_skip_all "shirudo did not stay around"

# ptrace(PTRACE_ATTACH): 0 attached (and detached again), 1 refused by
# the seal, 3 refused otherwise.
ATTACH='
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
pid = int(sys.argv[1])
if libc.ptrace(16, pid, None, None) == 0:
    libc.ptrace(17, pid, None, None)
    sys.exit(0)
sys.exit(1 if ctypes.get_errno() == 13 else 3)
'
# perf_event_open(PERF_COUNT_SW_CPU_CLOCK) bound to a task: the same
# exit codes.
PERF='
import ctypes, os, struct, sys
nr = {"x86_64": 298, "aarch64": 241, "riscv64": 241}.get(os.uname().machine)
if nr is None:
    sys.exit(4)
libc = ctypes.CDLL(None, use_errno=True)
pid = os.getpid() if sys.argv[1] == "self" else int(sys.argv[1])
attr = ctypes.create_string_buffer(
    struct.pack("IIQQQQQQQ", 1, 64, 0, 0, 0, 0, 0, 0, 0), 64)
fd = libc.syscall(nr, attr, pid, -1, -1, 0)
if fd >= 0:
    os.close(fd)
    sys.exit(0)
sys.exit(1 if ctypes.get_errno() == 13 else 3)
'

test_expect_success 'root cannot ptrace-attach to a running shirudo' '
	python3 -c "$ATTACH" "$PID"; [ "$?" = 1 ]
'

if python3 -c "$PERF" self 2>/dev/null; then
	test_expect_success 'root cannot bind a perf event to a running shirudo' '
		python3 -c "$PERF" "$PID"; [ "$?" = 1 ]
	'
else
	echo "# perf_event_open is unavailable here; the perf case is not run"
fi

test_expect_success 'the task is unharmed and finishes once released' '
	[ -d "/proc/$PID" ] &&
	python3 -c "
import os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
os.write(fd, b\"x\")
os.close(fd)" "$W/fifo" &&
	wait "$PID"; PID=; true
'

test_done
