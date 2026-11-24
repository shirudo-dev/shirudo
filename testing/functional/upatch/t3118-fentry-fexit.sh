#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3118 -- live fentry and fexit programs on one function: both links
# attach, the load and get name each kind, the fentry program sees a call
# with its arguments and follows a pointer among them, the fexit program
# sees a call that succeeded and a call the kernel refused, each with the
# arguments as passed and the value returned, and an unload detaches
# both.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-fentry-fexit
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
DIR="/run/shirudo/bpffs/upatches/$NAME"
WORK=$(mktemp -d)
trap 'if [ -e "$DIR/link_0" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi; rm -rf "$WORK"' EXIT

for fixture in "$LOAD" "$UNLOAD"; do
	[ -s "$fixture" ] || test_skip_all "missing fentry and fexit fixture: $fixture"
done

test_expect_success 'both links are pinned, and the load names each kind' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >"$WORK/load.log" 2>&1 &&
	[ -e "$DIR/link_0" ] && [ -e "$DIR/link_1" ] &&
	grep -q "program 0 (fentry) pinned at $DIR/link_0" "$WORK/load.log" &&
	grep -q "program 1 (fexit) pinned at $DIR/link_1" "$WORK/load.log"
'

test_expect_success 'get reports both kinds and the function' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
upatch = json.load(open(sys.argv[1], encoding="utf-8"))["upatch"]
assert sorted(p["location"] for p in upatch["programs"]) == \
    ["fentry/vfs_fallocate", "fexit/vfs_fallocate"], upatch
PY
'

# The fixture watches the length 1234567 alone. A range whose end does not
# fit a file offset fails in vfs_fallocate() itself, on every file system,
# with EFBIG.
test_expect_success 'a call that succeeds and a call that fails run through' '
	python3 - "$WORK/file" >"$WORK/inode" <<'PY'
import errno
import os
import sys
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
os.posix_fallocate(fd, 0, 1234567)
os.posix_fallocate(fd, 0, 4096)
try:
    os.posix_fallocate(fd, 2 ** 63 - 1234567, 1234567)
except OSError as e:
    assert e.errno == errno.EFBIG, e
else:
    raise AssertionError("a range past the largest offset was allocated")
print(os.fstat(fd).st_ino)
PY
'

test_expect_success 'each program saw both calls, with the arguments and the result' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" "$(cat "$WORK/inode")" <<'PY'
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
assert entry_calls == 2 and entry_inode == int(sys.argv[2]), values
assert exit_ok == 1 and exit_failed == 1, values
assert exit_errno == errno.EFBIG, values
assert exit_offset == 2 ** 63 - 1234567, values
PY
'

test_expect_success 'unload removes the links' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$DIR/link_0" ] && [ ! -e "$DIR/link_1" ]
'

test_done
