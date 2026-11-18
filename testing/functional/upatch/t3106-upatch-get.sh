#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3106 -- `shirudo upatch get <name>` dumps the BPF line info (source)
# of a LOADED upatch read from the kernel (the BTF the signed gen_loader
# installed). Loads the marker fentry upatch, asserts `get` shows the
# marker source, in text and in its JSON form with the payload the
# artifact names and the runs the kernel skipped of its one program, then
# unloads + cleans up on EXIT.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-marker
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
WORK=$(mktemp -d)

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing marker fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing marker unload fixture"
"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "load failed"

test_expect_success 'upatch get dumps the loaded source line from the kernel' '
	"$SHIRUDO_BIN" upatch get "$NAME" 2>/dev/null | grep -q "shirudo_test_marker"
'

test_expect_success 'its JSON form names the program, payload and source' '
	"$SHIRUDO_BIN" upatch get "$NAME" >"$WORK/get.txt" &&
	"$SHIRUDO_BIN" upatch get "$NAME" --json >"$WORK/get.json" &&
	"$SHIRUDO_BIN" upatch info --json "$LOAD" >"$WORK/info.json" &&
	python3 - "$WORK/get.json" "$WORK/info.json" "$WORK/get.txt" <<'\''PY'\''
import json, re, sys
doc = json.load(open(sys.argv[1]))
payload = json.load(open(sys.argv[2]))["payload_sha256"]
text = open(sys.argv[3]).read()
assert set(doc) == {"schema", "upatch"} and doc["schema"] == 1, doc
u = doc["upatch"]
assert set(u) == {"name", "location", "prog_id", "loaded_at", "age",
                  "payload_sha256", "missed_runs", "programs", "source",
                  "maps"}, u
assert u["name"] == "shirudo-test-marker"
assert u["location"] == "fentry/do_nanosleep"
assert u["prog_id"] > 0
assert re.search(r"^Program ID: +%d$" % u["prog_id"], text, re.M)
assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", u["loaded_at"])
assert u["age"]
assert u["payload_sha256"] == payload
assert isinstance(u["missed_runs"], int) and u["missed_runs"] >= 0, u
assert u["programs"] == [{"location": "fentry/do_nanosleep",
                          "missed_runs": u["missed_runs"]}], u
assert re.search(r"^Missed runs: +%d$" % u["missed_runs"], text, re.M)
lines = [(f["path"], line["line"], line["src"])
         for f in u["source"]["files"] for line in f["lines"]]
assert any(path.endswith("/marker.bpf.c") and n > 0 and
           "shirudo_test_marker" in src for path, n, src in lines), lines
assert u["maps"] == []
PY
'

test_expect_success 'a name that is not loaded has no JSON form' '
	! "$SHIRUDO_BIN" upatch get shirudo-test-not-loaded --json \
		>"$WORK/missing.json" 2>/dev/null &&
	[ ! -s "$WORK/missing.json" ]
'

test_done
