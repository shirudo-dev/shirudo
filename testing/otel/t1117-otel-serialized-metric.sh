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
if [ "${SHIRUDO_TEST_MODE:-legacy}" = verity ]; then
	"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-otel"
	export SHIRUDO_TEST_OTEL_PORT=5444
elif [ -e "$CONFIG" ]; then
	cp "$CONFIG" "$WORK/config"
	CONFIG_EXISTED=1
fi
if systemctl is-active --quiet shirudo-map-export.timer; then TIMER_WAS_ACTIVE=1; fi
restore() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && kill "$SERVER" >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && wait "$SERVER" 2>/dev/null || true
	if [ -e "$SERIALIZER_PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi
	if [ "${SHIRUDO_TEST_MODE:-legacy}" != verity ]; then
		if [ "$CONFIG_EXISTED" -eq 1 ]; then cp "$WORK/config" "$CONFIG"; else rm -f "$CONFIG"; fi
	fi
	[ "$TIMER_WAS_ACTIVE" -eq 1 ] && systemctl start shirudo-map-export.timer >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap restore EXIT
systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
cat >"$WORK/check-batch.py" <<'PY'
import json, sys
bodies = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(bodies) == 4
for index, expected in enumerate((10, 10, 10, 0)):
    metrics = {m["name"]: m for m in bodies[index]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}
    assert metrics["shirudo.serialized.packets"]["sum"]["dataPoints"][0]["asInt"] == str(expected)
    byte_count = 150 if expected else 0
    assert metrics["shirudo.serialized.bytes"]["sum"]["dataPoints"][0]["asInt"] == str(byte_count)
PY

cat >"$WORK/otel-batch.py" <<'PY'
import http.server, json, pathlib, sys
port_file, body_file = map(pathlib.Path, sys.argv[1:3])
bodies = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        bodies.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        body_file.write_text(json.dumps(bodies))
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 1
port_file.write_text(str(server.server_port))
while len(bodies) < 4:
    server.handle_request()
PY

cat >"$WORK/service.py" <<'PY'
import http.server, json, os, pathlib, sys, time
port_file, body_file = map(pathlib.Path, sys.argv[1:3])
requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        requests.append((self.path, json.loads(payload)))
        body_file.write_text(json.dumps(requests))
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", int(os.environ.get("SHIRUDO_TEST_OTEL_PORT", "0"))), Handler)
server.timeout = 1
port_file.write_text(str(server.server_port))
deadline = time.monotonic() + 30
while len(requests) < 2 and time.monotonic() < deadline:
    server.handle_request()
if len(requests) != 2:
    raise SystemExit("expected OTLP log and metric requests")
PY

cat >"$WORK/check-service.py" <<'PY'
import json, sys
requests = json.load(open(sys.argv[1], encoding="utf-8"))
assert sorted(path for path, _ in requests) == ["/v1/logs", "/v1/metrics"]
doc = next(body for path, body in requests if path == "/v1/metrics")
metrics = {m["name"]: m for m in doc["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]}
assert metrics["shirudo.serialized.packets"]["sum"]["dataPoints"][0]["asInt"] == "10"
assert metrics["shirudo.serialized.bytes"]["sum"]["dataPoints"][0]["asInt"] == "150"
PY

test_expect_success 'serialized multi-page metrics preserve peek and drain intervals' '
	python3 "$WORK/otel-batch.py" "$WORK/otel.port" "$WORK/bodies.json" &
	SERVER=$!;
	i=0; while test ! -s "$WORK/otel.port" && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch map "$NAME" counters --otel --otel-endpoint="http://127.0.0.1:$port" --peek &&
	"$SHIRUDO_BIN" upatch map "$NAME" counters --otel --otel-endpoint="http://127.0.0.1:$port" --peek &&
	"$SHIRUDO_BIN" upatch map "$NAME" counters --otel --otel-endpoint="http://127.0.0.1:$port" &&
	"$SHIRUDO_BIN" upatch map "$NAME" counters --otel --otel-endpoint="http://127.0.0.1:$port" &&
	wait "$SERVER" || return 1;
	SERVER="";
	python3 "$WORK/check-batch.py" "$WORK/bodies.json" &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 || return 1;
	python3 "$WORK/service.py" "$WORK/service.port" "$WORK/service.body" &
	SERVER=$!;
	i=0; while test ! -s "$WORK/service.port" && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	test -s "$WORK/service.port" &&
	port=$(cat "$WORK/service.port") &&
	{ [ "${SHIRUDO_TEST_MODE:-legacy}" = verity ] ||
	printf "%s\n" "map_export.otel_endpoint = http://127.0.0.1:$port" "map_export.otel_insecure = true" "map_export.otel_retries = 0" >"$CONFIG"; } &&
	if ! systemctl start shirudo-map-export.service; then
		systemctl status shirudo-map-export.service --no-pager >&2 || true
		journalctl -u shirudo-map-export.service --no-pager -n 100 >&2 || true
		return 1
	fi && wait "$SERVER" || return 1;
	SERVER="";
	systemctl show shirudo-map-export.service -p ExecMainStatus --value | grep -qx 0 &&
	python3 "$WORK/check-service.py" "$WORK/service.body"
'

test_done
