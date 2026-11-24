#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3120 -- live fentry.s, fmod_ret.s and fexit.s programs on the entry
# point of chdir(2): the three links attach and get names them, each
# program reads the path from user memory with a helper only a sleepable
# program may call, the fmod_ret.s program fails the one call it is
# written for and the caller gets its error, the other two see that
# call, and an unload detaches all three.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-sleepable
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
DIR="/run/shirudo/bpffs/upatches/$NAME"
WORK=$(mktemp -d)
trap 'if [ -e "$DIR/link_0" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi; rm -rf "$WORK"' EXIT

for fixture in "$LOAD" "$UNLOAD"; do
	[ -s "$fixture" ] || test_skip_all "missing sleepable fixture: $fixture"
done

# Exits with the errno of chdir(2) to the path, or 0.
change_dir() {
	python3 -c "import os, sys
try:
    os.chdir(sys.argv[1])
except OSError as e:
    sys.exit(e.errno)" "$1"
}

TEST_PATH=/shirudo-test-sleepable
ENOENT=2
EXDEV=18

test_expect_success 'the path does not exist before the load' '
	status=0 &&
	{ change_dir "$TEST_PATH" || status=$?; } &&
	[ "$status" = "$ENOENT" ]
'

test_expect_success 'the three links are pinned' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$DIR/link_0" ] && [ -e "$DIR/link_1" ] && [ -e "$DIR/link_2" ]
'

test_expect_success 'get reports the three kinds on the entry point' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
upatch = json.load(open(sys.argv[1], encoding="utf-8"))["upatch"]
locations = sorted(p["location"] for p in upatch["programs"])
kinds = [location.split("/")[0] for location in locations]
assert kinds == ["fentry", "fexit", "fmod_ret"], upatch
assert all(location.endswith("_sys_chdir") for location in locations), upatch
PY
'

test_expect_success 'the call the program refuses fails with its error' '
	status=0 &&
	{ change_dir "$TEST_PATH" || status=$?; } &&
	[ "$status" = "$EXDEV" ]
'

test_expect_success 'a call it lets through still runs' '
	change_dir /
'

test_expect_success 'the entry and the exit program saw the refused call' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
maps = doc["upatch"]["maps"]
seen = next(map_data for map_data in maps if map_data["name"] == "seen")
values = {int(entry["key"]): int(str(entry["value"]), 0)
          for entry in seen["entries"]}
assert values == {0: 1, 1: 1}, values
PY
'

test_expect_success 'unload removes the links and the refusal' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$DIR/link_0" ] && [ ! -e "$DIR/link_2" ] &&
	status=0 &&
	{ change_dir "$TEST_PATH" || status=$?; } &&
	[ "$status" = "$ENOENT" ]
'

test_done
