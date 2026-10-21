#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1117 -- serializer-to-OTLP metric coverage using a host-built fixture.

cd "$(dirname "$0")"
. ../integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemctl"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-serialized-metric
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
SERIALIZER_PIN="/run/shirudo/bpffs/upatches/$NAME/serializers/counters"
CONFIG=/etc/shirudo/shirudo.conf
WORK=$(mktemp -d)
SERVER=""
CONFIG_EXISTED=0
TIMER_WAS_ACTIVE=0
[ -s "$LOAD" ] || test_skip_all "missing serialized metric fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing serialized metric unload fixture"
systemctl cat shirudo-map-export.service >/dev/null 2>&1 || test_skip_all "map-export service is not installed"
if [ -e "$CONFIG" ]; then cp "$CONFIG" "$WORK/config"; CONFIG_EXISTED=1; fi
if systemctl is-active --quiet shirudo-map-export.timer; then TIMER_WAS_ACTIVE=1; fi
restore() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && kill "$SERVER" >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && wait "$SERVER" 2>/dev/null || true
	if [ -e "$SERIALIZER_PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi
	if [ "$CONFIG_EXISTED" -eq 1 ]; then cp "$WORK/config" "$CONFIG"; else rm -f "$CONFIG"; fi
	[ "$TIMER_WAS_ACTIVE" -eq 1 ] && systemctl start shirudo-map-export.timer >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap restore EXIT
systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
cat >"$WORK/check.py" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
doc = json.load(open(sys.argv[2], encoding="utf-8"))
assert meta["path"] == "/v1/metrics"
metrics = {m["name"]: m for m in doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}
assert set(metrics) == {"shirudo.serialized.packets", "shirudo.serialized.bytes"}
assert metrics["shirudo.serialized.packets"]["unit"] == "1"
assert metrics["shirudo.serialized.bytes"]["unit"] == "By"
for metric in metrics.values():
    series = metric["sum"]
    assert series["aggregationTemporality"] == 2
    assert series["isMonotonic"] is True
    point = series["dataPoints"][0]
    assert point["startTimeUnixNano"] == "1699999990000000000"
    assert point["timeUnixNano"] == "1700000000000000000"
assert metrics["shirudo.serialized.packets"]["sum"]["dataPoints"][0]["asInt"] == "10"
assert metrics["shirudo.serialized.bytes"]["sum"]["dataPoints"][0]["asInt"] == "150"
PY

test_expect_success 'serialized counters become cumulative OTLP metrics' '
	python3 ../helper/otel-mock.py success "$WORK/otel.port" "$WORK/otel.body" "$WORK/otel.meta" &
	SERVER=$!;
	i=0; while test ! -s "$WORK/otel.port" && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	printf "%s\n" "map_export.otel_endpoint = http://127.0.0.1:$port" "map_export.otel_insecure = true" "map_export.otel_retries = 0" >"$CONFIG" &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	test -e "$SERIALIZER_PIN" &&
	systemctl start shirudo-map-export.service &&
	wait "$SERVER"; SERVER="";
	systemctl show shirudo-map-export.service -p ExecMainStatus --value | grep -qx 0 &&
	python3 "$WORK/check.py" "$WORK/otel.meta" "$WORK/otel.body"
'

test_done
