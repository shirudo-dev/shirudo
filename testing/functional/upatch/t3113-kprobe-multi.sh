#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3113 -- live kprobe.multi and kretprobe.multi: both links attach,
# status names them, both programs run and report the runs the kernel
# skipped of each, an unload detaches them, and a name the kernel does
# not know fails the whole link.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-kprobe-multi
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
MISSING="$FIXTURES/shirudo-test-kprobe-multi-missing.upatch"
DIR="/run/shirudo/bpffs/upatches/$NAME"
WORK=$(mktemp -d)
trap 'if [ -e "$DIR/link_0" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi; rm -rf "$WORK"' EXIT

for fixture in "$LOAD" "$UNLOAD" "$MISSING"; do
	[ -s "$fixture" ] || test_skip_all "missing kprobe multi fixture: $fixture"
done

"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >"$WORK/load.log" 2>&1 ||
	test_skip_all "kernel does not support this kprobe.multi load"

test_expect_success 'both links are pinned' '
	[ -e "$DIR/link_0" ] && [ -e "$DIR/link_1" ]
'

test_expect_success 'status reports the kind and the function count' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["upatch"]["location"] == "kprobe.multi (2 funcs)", doc
PY
'

test_expect_success 'entry and return programs both run' '
	cat /proc/version >/dev/null &&
	echo x >"$WORK/out" &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	python3 - "$WORK/get.json" <<'PY'
import json
import sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
maps = doc["upatch"]["maps"]
hits = next(map_data for map_data in maps if map_data["name"] == "hits")
values = [entry["value"] for entry in hits["entries"]]
assert len(values) == 2, doc
for value in values:
    assert int(str(value), 0) > 0, doc
PY
'

test_expect_success 'get and status report the runs the kernel skipped' '
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	"$SHIRUDO_BIN" status --json >"$WORK/status.json" &&
	python3 - "$WORK/get.json" "$WORK/status.json" <<'PY'
import json
import sys
upatch = json.load(open(sys.argv[1], encoding="utf-8"))["upatch"]
loaded = json.load(open(sys.argv[2], encoding="utf-8"))["upatches_loaded"]
programs = upatch["programs"]
assert sorted(p["location"] for p in programs) == \
    ["kprobe.multi (2 funcs)", "kretprobe.multi (2 funcs)"], upatch
assert all(isinstance(p["missed_runs"], int) for p in programs), upatch
assert upatch["missed_runs"] == sum(p["missed_runs"] for p in programs), upatch
row = next(u for u in loaded if u["name"] == "shirudo-test-kprobe-multi")
assert isinstance(row["missed_runs"], int), row
assert row["missed_runs"] >= upatch["missed_runs"], (row, upatch)
PY
'

test_expect_success 'unload removes the links' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$DIR/link_0" ] && [ ! -e "$DIR/link_1" ]
'

test_expect_success 'a name the kernel lacks fails the link as a missing target' '
	status=0 &&
	{ "$SHIRUDO_BIN" upatch load "$MISSING" --no-precheck \
		--report="$WORK/report.json" >/dev/null 2>&1 || status=$?; } &&
	[ "$status" = 2 ] &&
	[ "$(report_field category <"$WORK/report.json")" = attach_target_missing ] &&
	[ ! -e /run/shirudo/bpffs/upatches/shirudo-test-kprobe-multi-missing/link ]
'

test_done
