#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=kernel-obs
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
WORK=$(mktemp -d)
. ./end2end/otel-export.sh
otel_setup

cleanup()
{
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"

cat >"$WORK/check.py" <<'PYTHON'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert len(records) == 1 and records[0].get("map") == "dns", records
addresses = {item["address"]: item for item in records[0].get("records", [])}
for address, name in (("203.0.113.10", ".".join(["a"] * 127)),
                      ("203.0.113.75", "many.example")):
    record = addresses.get(address)
    assert record is not None, records
    assert any(item["name"] == name for item in record["names"]), record
assert records[0]["interval"]["overflow"] == 0, records
assert records[0]["interval"]["lost"] == 0, records
PYTHON

cat >"$WORK/check-empty.py" <<'PYTHON'
import json
import sys

records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
assert len(records) == 1 and records[0].get("map") == "dns", records
assert records[0].get("records") == [], records
PYTHON

test_expect_success 'DNS observations use real loopback UDP traffic' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	python3 end2end/kernel_obs_events.py dns-long &&
	python3 end2end/kernel_obs_events.py dns-many &&
	otel_export dns "$OTEL_OUT/t9104-dns.ndjson" &&
	python3 "$WORK/check.py" "$OTEL_OUT/t9104-dns.ndjson" &&
	otel_export dns "$OTEL_OUT/t9104-dns-empty.ndjson" &&
	python3 "$WORK/check-empty.py" "$OTEL_OUT/t9104-dns-empty.ndjson"
'

test_done
