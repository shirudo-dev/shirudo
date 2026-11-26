#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3121 -- the upatch pwru --shirudo-upatch exports records, from its
# kprobe.multi programs, the packets its pcap filter matches, before and
# after they have a link-layer header, and only those, with the reason of
# a drop, its decoder reads them back, and an export sends them to an OTLP
# collector.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=pwru
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
WORK=$(mktemp -d)
SEND=$WORK/send.py
DROP=$WORK/drop.py
CHECK=$WORK/check.py
COLLECTOR=$WORK/collector.py
CHECK_OTLP=$WORK/check-otlp.py
SERVER=""

restore() {
	[ -n "$SERVER" ] && kill "$SERVER" >/dev/null 2>&1 || true
	[ -n "$SERVER" ] && wait "$SERVER" 2>/dev/null || true
	if [ -e "$PINDIR" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing pwru fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing pwru unload fixture"

# The fixture's filter: udp and host 127.0.0.2 and port 4242.
cat >"$SEND" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, port))
s.settimeout(5)
for _ in range(3):
    s.sendto(b"pwru", (host, port))
    s.recv(16)
PY
# To a port nothing listens on, which UDP drops for want of a socket.
cat >"$DROP" <<'PY'
import socket, sys
host, sport, dport = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host, sport))
s.sendto(b"pwru", (host, dport))
PY
cat >"$CHECK" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
records = doc["records"]
assert records, doc
echo = "127.0.0.2:4242->127.0.0.2:4242(udp)"
dropped = "127.0.0.2:4243->127.0.0.2:4242(udp)"
for r in records:
    assert r.get("tuple") in (echo, dropped), r
    assert r["skb"].startswith("0x") and r["len"] > 0, r
    assert r["protocol"] == "IPv4", r
seen = {}
for r in records:
    if r["tuple"] == echo:
        seen.setdefault(r["func"], set()).add(r["skb"])
# Before the Ethernet header, on the way out, and with it, on the way
# in: loopback hands the sk_buff it sends to the receive path.
for func in ("ip_output", "__dev_queue_xmit", "dev_hard_start_xmit",
             "__netif_receive_skb_one_core", "ip_rcv_core",
             "ip_protocol_deliver_rcu"):
    assert func in seen, (func, sorted(seen))
assert seen["ip_output"] & seen["ip_protocol_deliver_rcu"], seen
drops = [r for r in records
         if r["tuple"] == dropped and r["func"] == "sk_skb_reason_drop"]
assert drops, records
# Neither SKB_NOT_DROPPED_YET nor SKB_CONSUMED.
assert all(r["reason"] > 1 for r in drops), drops
assert doc["interval"]["peek"] is True, doc["interval"]
assert doc["interval"]["used"] >= len(records), doc["interval"]
assert doc["interval"]["overflow"] == 0, doc["interval"]
PY
cat >"$COLLECTOR" <<'PY'
import http.server, json, pathlib, sys
port_file, body_file = map(pathlib.Path, sys.argv[1:3])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body_file.write_text(json.dumps({"path": self.path,
                                         "body": json.loads(body)}))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *args): pass
server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 30
port_file.write_text(str(server.server_port))
server.handle_request()
PY
cat >"$CHECK_OTLP" <<'PY'
import json, sys
def fields(value):
    return {kv["key"]: kv["value"] for kv in value["kvlistValue"]["values"]}
sent = json.load(open(sys.argv[1], encoding="utf-8"))
assert sent["path"] == "/v1/logs", sent["path"]
log = sent["body"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
body = fields(log["body"])
assert body["upatch"]["stringValue"] == "pwru", body
records = [fields(r) for r in body["records"]["arrayValue"]["values"]]
assert records, body
assert {r["tuple"]["stringValue"] for r in records} == \
    {"127.0.0.2:4242->127.0.0.2:4242(udp)",
     "127.0.0.2:4243->127.0.0.2:4242(udp)"}, records
drained = json.load(open(sys.argv[2], encoding="utf-8"))
assert not drained["records"], drained
PY

test_expect_success 'the pwru upatch loads with every probe attached' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null &&
	[ -d "$PINDIR" ] &&
	"$SHIRUDO_BIN" upatch list 2>/dev/null | grep -q "$NAME"
'

test_expect_success 'traffic the filter matches and traffic it does not' '
	python3 "$SEND" 127.0.0.2 4242 &&
	python3 "$SEND" 127.0.0.3 4243 &&
	python3 "$SEND" 127.0.0.2 4243 &&
	python3 "$DROP" 127.0.0.2 4243 4242
'

test_expect_success 'the decoder returns the matching packets alone, and the drop' '
	"$SHIRUDO_BIN" upatch map "$NAME" events --json --peek \
		>"$WORK/events.json" &&
	python3 "$CHECK" "$WORK/events.json"
'

test_expect_success 'an export sends them to an OTLP collector and drains them' '
	python3 "$COLLECTOR" "$WORK/otlp.port" "$WORK/otlp.json" &
	SERVER=$!;
	i=0; while test ! -s "$WORK/otlp.port" && test "$i" -lt 100; do i=$((i+1)); sleep .1; done;
	test -s "$WORK/otlp.port" &&
	port=$(cat "$WORK/otlp.port") &&
	"$SHIRUDO_BIN" upatch map "$NAME" events --otel \
		--otel-endpoint="http://127.0.0.1:$port" &&
	wait "$SERVER" || return 1;
	SERVER="";
	"$SHIRUDO_BIN" upatch map "$NAME" events --json --peek \
		>"$WORK/drained.json" &&
	python3 "$CHECK_OTLP" "$WORK/otlp.json" "$WORK/drained.json"
'

test_expect_success 'the UNLOAD directive detaches every probe' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
		>/dev/null 2>&1 &&
	[ ! -e "$PINDIR" ]
'

test_done
