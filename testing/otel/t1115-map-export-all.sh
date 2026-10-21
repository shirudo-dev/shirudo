#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ../integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-map-export
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
CONFIG=/etc/shirudo/shirudo.conf
WORK=$(mktemp -d)
SERVER=""
CONFIG_EXISTED=0
if [ -e "$CONFIG" ]; then cp "$CONFIG" "$WORK/config"; CONFIG_EXISTED=1; fi
restore() {
	[ -n "$SERVER" ] && kill "$SERVER" >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && wait "$SERVER" 2>/dev/null || true
	if [ -e "$PIN" ]; then "$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true; fi
	if [ "$CONFIG_EXISTED" -eq 1 ]; then cp "$WORK/config" "$CONFIG"; else rm -f "$CONFIG"; fi
	rm -rf "$WORK"
}
trap restore EXIT
[ -s "$LOAD" ] || test_skip_all "missing map-export fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing map-export unload fixture"

cat >"$WORK/check-maps.py" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
log = next(r for r in records if isinstance(r, dict) and r.get("map") == "first")
metric = next(r for r in records if isinstance(r, list))
assert log["upatch"] == sys.argv[2]
assert log["schema"] == 1
assert isinstance(log["data"], dict)
assert metric[0]["name"] == "shirudo.map_export.second"
PY
cat >"$WORK/otel.py" <<'PY'
import http.server, json, pathlib, sys
port_file, meta_file = map(pathlib.Path, sys.argv[1:3])
paths, tenants = [], []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        paths.append(self.path); tenants.append(self.headers.get("X-Tenant-ID", ""))
        meta_file.write_text(json.dumps({"paths": paths, "tenants": tenants}))
        body = b"{}"; self.send_response(200)
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body); self.server.done = len(paths) >= 4
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.done = False; server.timeout = 5; port_file.write_text(str(server.server_port))
while not server.done: server.handle_request()
PY
cat >"$WORK/check-otel.py" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding="utf-8"))
assert len(meta["paths"]) == 4, meta
assert meta["tenants"] == ["tenant-config-0000"] * 2 + ["tenant-uuid-1234"] * 2, meta
assert sum(p.endswith("/v1/logs") for p in meta["paths"]) == 2
assert sum(p.endswith("/v1/metrics") for p in meta["paths"]) == 2
PY

test_expect_success '--all exports one detailed JSON record per loaded map' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch map --all --json="$WORK/maps.ndjson" &&
	python3 "$WORK/check-maps.py" "$WORK/maps.ndjson" "$NAME"
'

test_expect_success '--all auto exports mixed metric and log maps' '
	python3 "$WORK/otel.py" "$WORK/otel.port" "$WORK/otel.meta" &
	SERVER=$!;
	i=0; while test ! -s "$WORK/otel.port" && test "$i" -lt 100; do i=$((i+1)); sleep .02; done;
	test -s "$WORK/otel.port" &&
	port=$(cat "$WORK/otel.port") &&
	printf "%s\n" "map_export.tenant_id = tenant-config-0000" >"$CONFIG" &&
	"$SHIRUDO_BIN" upatch map --all --otel --otel-endpoint="http://127.0.0.1:$port/base" &&
	"$SHIRUDO_BIN" upatch map --all --otel --tenant-id=tenant-uuid-1234 --otel-endpoint="http://127.0.0.1:$port/base";
	kill "$SERVER" >/dev/null 2>&1 || true; wait "$SERVER" 2>/dev/null || true; SERVER="";
	python3 "$WORK/check-otel.py" "$WORK/otel.meta"
'

test_done
