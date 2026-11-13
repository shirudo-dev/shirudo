#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3107 -- live uprobe.multi, uretprobe.multi and sleepable uprobe.multi.s
# coverage using host-built target fixtures.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-uprobe-multi
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
RET_NAME=shirudo-test-uretprobe-multi
RET_LOAD="$FIXTURES/$RET_NAME.upatch"
RET_UNLOAD="$FIXTURES/$RET_NAME.unload.upatch"
SLEEP_NAME=shirudo-test-uprobe-multi-sleepable
SLEEP_LOAD="$FIXTURES/$SLEEP_NAME.upatch"
SLEEP_UNLOAD="$FIXTURES/$SLEEP_NAME.unload.upatch"
TARGET="$FIXTURES/shirudo-test-uprobe-target"
RUNTIME=/tmp/shirudo-test-uprobe-target
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
RET_PIN="/run/shirudo/bpffs/upatches/$RET_NAME/link"
SLEEP_PIN="/run/shirudo/bpffs/upatches/$SLEEP_NAME/link"
WORK=$(mktemp -d)
cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true
	fi
	if [ -e "$RET_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$RET_UNLOAD" --no-precheck >/dev/null 2>&1 || true
	fi
	if [ -e "$SLEEP_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$SLEEP_UNLOAD" --no-precheck >/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

for fixture in "$LOAD" "$UNLOAD" "$RET_LOAD" "$RET_UNLOAD" "$SLEEP_LOAD" \
    "$SLEEP_UNLOAD" "$TARGET"; do
	[ -s "$fixture" ] || test_skip_all "missing uprobe fixture: $fixture"
done

cp "$TARGET" "$RUNTIME"
cp "$RUNTIME" "$WORK/target.original"
cp /bin/true "$RUNTIME"
test_expect_success 'a changed target build ID is rejected before BPF load' '
	cat=$("$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		--report=- 2>/dev/null | report_field category) &&
	[ "$cat" = binary_mismatch ] &&
	[ ! -e "$PIN" ]
'
cp "$WORK/target.original" "$RUNTIME"

"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "kernel does not support this uprobe.multi load"

test_expect_success 'status reports the target path and two functions' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/before.json" &&
	python3 - "$WORK/before.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["upatch"]["location"] == \
    "uprobe.multi//tmp/shirudo-test-uprobe-target (2 funcs)"
PY
'

test_expect_success 'fooFunc and barFunc both execute the same upatch program' '
	"$RUNTIME" &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/after.json" &&
	python3 - "$WORK/after.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
hits = next(m for m in doc["upatch"]["maps"] if m["name"] == "hits")
assert int(hits["entries"][0]["value"], 0) == 2
PY
'

test_expect_success 'uretprobe.multi loads, runs on both returns and unloads' '
	"$SHIRUDO_BIN" upatch load "$RET_LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$RET_PIN" ] &&
	"$RUNTIME" &&
	"$SHIRUDO_BIN" upatch get "$RET_NAME" --json >"$WORK/ret.json" &&
	python3 - "$WORK/ret.json" <<'PY' &&
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["upatch"]["location"] == \
    "uretprobe.multi//tmp/shirudo-test-uprobe-target (2 funcs)", doc
hits = next(m for m in doc["upatch"]["maps"] if m["name"] == "hits")
assert int(hits["entries"][0]["value"], 0) == 2, doc
PY
	"$SHIRUDO_BIN" upatch unload "$RET_UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$RET_PIN" ]
'

test_expect_success 'a sleepable uprobe.multi.s reads user memory on both calls and unloads' '
	"$SHIRUDO_BIN" upatch load "$SLEEP_LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$SLEEP_PIN" ] &&
	"$RUNTIME" &&
	"$SHIRUDO_BIN" upatch get "$SLEEP_NAME" --json >"$WORK/sleep.json" &&
	python3 - "$WORK/sleep.json" <<'PY' &&
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["upatch"]["location"] == \
    "uprobe.multi//tmp/shirudo-test-uprobe-target (2 funcs)", doc
hits = next(m for m in doc["upatch"]["maps"] if m["name"] == "hits")
assert int(hits["entries"][0]["value"], 0) == 2, doc
PY
	"$SHIRUDO_BIN" upatch unload "$SLEEP_UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$SLEEP_PIN" ]
'

test_done
