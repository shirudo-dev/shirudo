#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3119 -- live fmod_ret programs. On security_task_setnice(), a target
# on every kernel, the program fails the one call it is written for, and
# the caller gets its error. On vfs_fallocate(), a target only by the tag
# of a kernel built with CONFIG_BPF_FMODRET_SCAN, the same holds, an
# fentry program runs before the skip, an fexit program sees the error
# with the arguments of the skipped call, and a program that returns an
# error outside the tag's list is refused. A kernel without tags refuses
# the function.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-fmod-ret
TAGGED=shirudo-test-fmod-ret-tagged
UNLISTED=shirudo-test-fmod-ret-unlisted
OBSERVERS=shirudo-test-fentry-fexit
PINS=/run/shirudo/bpffs/upatches
WORK=$(mktemp -d)

load() {
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck \
		>/dev/null 2>&1
}

unload() {
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$1.unload.upatch" \
		--no-precheck >/dev/null 2>&1
}

# Load a fixture the kernel has to refuse, and check how the load failed.
refused() {
	status=0
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck \
		--report="$WORK/report.json" >/dev/null 2>&1 || status=$?
	[ "$status" = 1 ] &&
	[ "$(report_field category <"$WORK/report.json")" = verifier_rejected ] &&
	[ "$(report_field phase <"$WORK/report.json")" = payload_load ] &&
	report_field verifier_log <"$WORK/report.json" | grep -q "$2" &&
	[ ! -e "$PINS/$1" ]
}

# Each exits with the errno of the call, or 0.
set_nice() {
	python3 -c "import os, sys
try:
    os.setpriority(os.PRIO_PROCESS, 0, int(sys.argv[1]))
except OSError as e:
    sys.exit(e.errno)" "$1"
}

allocate() {
	python3 -c "import os, sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
try:
    os.posix_fallocate(fd, 0, int(sys.argv[2]))
except OSError as e:
    sys.exit(e.errno)" "$WORK/file" "$1"
}

restore() {
	for fixture in "$NAME" "$TAGGED" "$OBSERVERS"; do
		[ ! -d "$PINS/$fixture" ] || unload "$fixture" || true
	done
	rm -rf "$WORK"
}
trap restore EXIT

for fixture in "$NAME" "$TAGGED" "$OBSERVERS"; do
	[ -s "$FIXTURES/$fixture.upatch" ] &&
	[ -s "$FIXTURES/$fixture.unload.upatch" ] ||
		test_skip_all "missing fmod_ret fixture: $fixture"
done
[ -s "$FIXTURES/$UNLISTED.upatch" ] ||
	test_skip_all "missing fmod_ret fixture: $UNLISTED"

EOPNOTSUPP=95
EFBIG=27

test_expect_success 'the nice value is set before the load' '
	set_nice 17
'

test_expect_success 'the link is pinned and get reports the kind' '
	load "$NAME" &&
	[ -e "$PINS/$NAME/link" ] &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
location = doc["upatch"]["location"]
assert location == "fmod_ret/security_task_setnice", doc
PY
'

test_expect_success 'the call the program refuses fails with its error' '
	status=0 &&
	{ set_nice 17 || status=$?; } &&
	[ "$status" = "$EOPNOTSUPP" ]
'

test_expect_success 'a call it lets through still runs' '
	set_nice 16
'

test_expect_success 'the unload lets the refused call through again' '
	unload "$NAME" &&
	[ ! -e "$PINS/$NAME/link" ] &&
	set_nice 17
'

if grep -a -q "bpf_fmodret_retval:" /sys/kernel/btf/vmlinux; then
	test_expect_success 'a tagged function takes a program that returns a listed error' '
		load "$OBSERVERS" &&
		load "$TAGGED" &&
		[ -e "$PINS/$TAGGED/link" ]
	'

	test_expect_success 'the call it refuses fails with that error, another one runs' '
		status=0 &&
		{ allocate 1234567 || status=$?; } &&
		[ "$status" = "$EFBIG" ] &&
		allocate 4096
	'

	test_expect_success 'fentry runs before the skip, fexit sees its error and arguments' '
		"$SHIRUDO_BIN" upatch get "$OBSERVERS" --json >"$WORK/get.json" &&
		python3 - "$WORK/get.json" <<'PY'
import errno
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
maps = doc["upatch"]["maps"]
seen = next(map_data for map_data in maps if map_data["name"] == "seen")
values = {int(entry["key"]): int(str(entry["value"]), 0)
          for entry in seen["entries"]}
entry_calls, entry_inode, exit_ok, exit_failed, exit_errno, exit_offset = \
    (values[slot] for slot in range(6))
assert entry_calls == 1, values
assert exit_ok == 0 and exit_failed == 1, values
assert exit_errno == errno.EFBIG and exit_offset == 0, values
PY
	'

	test_expect_success 'the unload lets the refused call through again' '
		unload "$TAGGED" &&
		allocate 1234567 &&
		unload "$OBSERVERS"
	'

	test_expect_success 'a program that returns an error outside the list is refused' '
		refused "$UNLISTED" "should be 0 or one of"
	'
else
	test_expect_success 'a kernel without tags refuses the function' '
		refused "$TAGGED" "vfs_fallocate() is not modifiable"
	'
fi

test_done
