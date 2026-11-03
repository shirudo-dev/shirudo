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
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"

export_net_maps()
{
	for map in net socket; do
		otel_export "$map" "$OTEL_OUT/t9102-events.ndjson"
	done
}

cat >"$WORK/check.py" <<'PYTHON'
import json
import sys

expected = json.load(open(sys.argv[1], encoding="utf-8"))
documents = [json.loads(line) for line in
             open(sys.argv[2], encoding="utf-8")]
tables = {record["map"]: record["records"] for record in documents
          if isinstance(record, dict)}
assert set(tables) == {"net", "socket"}, documents
net = tables["net"]
sockets = tables["socket"]
assert any(r["address"] == "127.0.0.1" and r["proto"] == "tcp" and
           r["role"] == "initiator" and int(r["tx_packets"]) >= 1 and
           int(r["rx_packets"]) >= 1 for r in net), net
assert any(r["address"] == "127.0.0.1" and r["proto"] == "udp" and
           int(r["count"]) >= 1 for r in net), net
for item in expected["creations"]:
    assert any(r["operation"] == "create" and
               r["family"] == item["family"] and
               r["type"] == item["type"] and
               r["protocol"] == item["protocol"]
               for r in sockets), (item, sockets)
for family, operation in ((2, "sendmsg"), (1, "bind"),
                          (16, "sendmsg")):
    assert any(r["family"] == family and r["operation"] == operation
               for r in sockets), (family, operation, sockets)
for operation in ("bind", "connect", "listen", "accept", "sendmsg",
                  "recvmsg", "setsockopt", "shutdown", "socketpair"):
    assert any(r["family"] == 1 and r["operation"] == operation
               for r in sockets), (1, operation, sockets)
if expected["raw_created"]:
    assert any(r["family"] == 2 and r["type"] == 3 and
               r["protocol"] == 1 and r["operation"] == "sendmsg"
               for r in sockets), sockets
if any(r["family"] == 17 for r in sockets):
    assert any(r["family"] == 17 and
               r["operation"] in ("setsockopt", "sendmsg")
               for r in sockets), sockets
if any(r["family"] == 44 for r in sockets):
    assert any(r["family"] == 44 and
               r["operation"] in ("bind", "sendmsg")
               for r in sockets), sockets
if any(r["family"] == 40 for r in sockets):
    assert any(r["family"] == 40 and r["operation"] in
               ("bind", "connect", "sendmsg") for r in sockets), sockets
pass_ids = expected["fd_pass"]
assert any(r["operation"] == "sendmsg" and
           r["owner"]["known"] and
           r["owner"]["pid"] == pass_ids["owner_pid"] and
           r["actor"]["pid"] == pass_ids["actor_pid"]
           for r in sockets), (pass_ids, sockets)
for record in documents:
    if isinstance(record, dict):
        assert record["interval"]["overflow"] == 0, record
        assert record["interval"]["lost"] == 0, record
        for item in record["records"]:
            assert "path" not in item and "payload" not in item, item
PYTHON

test_expect_success 'socket map loads with the network serializers' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/net" &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/socket"
'

test_expect_success 'TCP, UDP and additional socket families are recorded' '
	python3 end2end/kernel_obs_events.py tcp &&
	python3 end2end/kernel_obs_events.py udp &&
	python3 end2end/kernel_obs_events.py sockets \
		>"$WORK/expected.json" &&
	export_net_maps &&
	python3 "$WORK/check.py" "$WORK/expected.json" \
		"$OTEL_OUT/t9102-events.ndjson"
'

test_done
