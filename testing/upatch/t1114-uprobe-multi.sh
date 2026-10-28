#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1114 -- live uprobe.multi coverage using host-built target fixtures.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-uprobe-multi
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
TARGET="$FIXTURES/shirudo-test-uprobe-target"
RUNTIME=/tmp/shirudo-test-uprobe-target
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
WORK=$(mktemp -d)
trap 'if [ -e "$PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi; rm -rf "$WORK"' EXIT

for fixture in "$LOAD" "$UNLOAD" "$TARGET"; do
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

test_done
