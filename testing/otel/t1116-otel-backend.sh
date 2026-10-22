#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1116 -- systemd map-export service and timer coverage.

cd "$(dirname "$0")"
. ../integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v systemctl >/dev/null 2>&1 || test_skip_all "no systemctl"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-otel-backend
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
CONFIG=/etc/shirudo/shirudo.conf
WORK=$(mktemp -d)
SERVER=""
CONFIG_EXISTED=0
TIMER_WAS_ACTIVE=0
[ -s "$LOAD" ] || test_skip_all "missing OTEL backend fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing OTEL backend unload fixture"
systemctl cat shirudo-map-export.service >/dev/null 2>&1 || test_skip_all "map-export service is not installed"
systemctl cat shirudo-map-export.timer >/dev/null 2>&1 || test_skip_all "map-export timer is not installed"
if [ -e "$CONFIG" ]; then cp "$CONFIG" "$WORK/config"; CONFIG_EXISTED=1; fi
if systemctl is-active --quiet shirudo-map-export.timer; then TIMER_WAS_ACTIVE=1; fi
restore() {
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && kill "$SERVER" >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && wait "$SERVER" 2>/dev/null || true
	if [ -e "$PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi
	if [ "$CONFIG_EXISTED" -eq 1 ]; then cp "$WORK/config" "$CONFIG"; else rm -f "$CONFIG"; fi
	[ "$TIMER_WAS_ACTIVE" -eq 1 ] && systemctl start shirudo-map-export.timer >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap restore EXIT
systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
cat >"$WORK/otel.py" <<'PY'
import http.server, json, pathlib, sys
port_file, meta_file = map(pathlib.Path, sys.argv[1:3])
paths = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        paths.append(self.path); meta_file.write_text(json.dumps({"paths": paths}))
        body = b"{}"; self.send_response(200)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 1; port_file.write_text(str(server.server_port))
while len(paths) < 4: server.handle_request()
PY
cat >"$WORK/check-otel.py" <<'PY'
import json, sys
paths = json.load(open(sys.argv[1], encoding="utf-8"))["paths"]
assert len(paths) == 4
assert sum(p.endswith("/v1/logs") for p in paths) == 2
assert sum(p.endswith("/v1/metrics") for p in paths) == 2
PY

test_expect_success 'map-export service delivers both decoder-backed maps' '
	python3 "$WORK/otel.py" "$WORK/otel.port" "$WORK/otel.meta" &
	SERVER=$!;
	i=0; while { test ! -s "$WORK/otel.port" || test ! -s "$WORK/otel.meta"; } && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	printf "%s\n" "map_export.otel_endpoint = http://127.0.0.1:$port" "map_export.otel_insecure = true" "map_export.otel_retries = 0" >"$CONFIG" &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	systemctl start shirudo-map-export.service &&
	systemctl start shirudo-map-export.timer;
	i=0; while test "$i" -lt 100; do count=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1], encoding=\"utf-8\"))[\"paths\"]))" "$WORK/otel.meta" 2>/dev/null || echo 0); test "$count" -ge 4 && break; i=$((i+1)); sleep .1; done;
	kill "$SERVER" >/dev/null 2>&1 || true; wait "$SERVER" 2>/dev/null || true; SERVER="";
	test "$count" -eq 4 &&
	python3 "$WORK/check-otel.py" "$WORK/otel.meta"
'

test_expect_success 'map-export timer does not overlap a running export' '
	systemctl stop shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl stop shirudo-map-export.service >/dev/null 2>&1 || true
	cat >"$WORK/slow-otel.py" <<'PY'
import http.server, json, pathlib, sys, threading, time
port_file, meta_file = map(pathlib.Path, sys.argv[1:3])
state = {"active": 0, "max_active": 0, "paths": [], "times": [], "completed": 0}
lock = threading.Lock()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with lock:
            state["active"] += 1
            state["max_active"] = max(state["max_active"], state["active"])
            state["paths"].append(self.path)
            state["times"].append(time.monotonic())
        time.sleep(3)
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        with lock:
            state["active"] -= 1
            state["completed"] += 1
            meta_file.write_text(json.dumps(state))
    def log_message(self, *args): pass
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
port_file.write_text(str(server.server_port))
while state["completed"] < 4:
    server.handle_request()
PY
	python3 "$WORK/slow-otel.py" "$WORK/slow.port" "$WORK/slow.meta" & SERVER=$!;
	i=0; while test ! -s "$WORK/slow.port" && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	port=$(cat "$WORK/slow.port") && test -n "$port" &&
	printf "%s\n" "map_export.otel_endpoint = http://127.0.0.1:$port" "map_export.otel_insecure = true" "map_export.otel_retries = 0" >"$CONFIG" || return 1;
	(systemctl start shirudo-map-export.service >/dev/null 2>&1) & service_start=$!;
	systemctl start shirudo-map-export.timer && wait "$service_start";
	i=0; while { test ! -s "$WORK/slow.meta" || test "$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['completed'])" "$WORK/slow.meta" 2>/dev/null || echo 0)" -lt 4; } && test "$i" -lt 300; do i=$((i+1)); sleep .1; done;
	kill "$SERVER" >/dev/null 2>&1 || true; wait "$SERVER" 2>/dev/null || true; SERVER="";
	python3 - "$WORK/slow.meta" <<'\''PY'\''
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
assert state["completed"] == 4
assert state["max_active"] == 1
assert sum(path.endswith("/v1/logs") for path in state["paths"]) == 2
assert sum(path.endswith("/v1/metrics") for path in state["paths"]) == 2
assert state["times"][2] - state["times"][1] >= 7
PY
'

test_done
