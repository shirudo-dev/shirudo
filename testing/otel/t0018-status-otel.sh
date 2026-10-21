#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ../test-lib.sh

S=../../shirudo

test_expect_success 'status --otel sends a structured keepalive log' '
	work=$(mktemp -d)
	python3 ../helper/otel-mock.py success "$work/port" "$work/body" \
		"$work/meta" &
	server=$!
	trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
	i=0
	while test ! -s "$work/port" && test "$i" -lt 100; do
		sleep .02
		i=$((i + 1))
	done
	port=$(cat "$work/port") &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --otel >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	test ! -s "$work/stdout" &&
	python3 - "$work/body" "$work/meta" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
meta = json.load(open(sys.argv[2]))
record = doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
values = {
    item["key"]: item["value"]
    for item in record["body"]["kvlistValue"]["values"]
}
assert meta["path"] == "/v1/logs"
assert record["eventName"] == "shirudo.keepalive"
assert {"schema", "status", "conditions", "tpm"} <= values.keys()
assert values["tpm"]["kvlistValue"]
status = values["status"]["stringValue"]
severity = {
    "ok": (9, "INFO"),
    "degraded": (13, "WARN"),
    "init-pending": (13, "WARN"),
    "lsm-off": (17, "ERROR"),
    "tampered": (17, "ERROR"),
}[status]
assert (record["severityNumber"], record["severityText"]) == severity
attrs = {item["key"]: item["value"] for item in record["attributes"]}
assert "shirudo.status" in attrs
assert "shirudo.version_id" in attrs
PY
'

test_expect_success 'status --json --otel keeps JSON output available' '
	work=$(mktemp -d)
	python3 ../helper/otel-mock.py success "$work/port" "$work/body" \
		"$work/meta" &
	server=$!
	trap "kill $server 2>/dev/null || true; wait $server 2>/dev/null || true; rm -rf $work" EXIT
	i=0
	while test ! -s "$work/port" && test "$i" -lt 100; do
		sleep .02
		i=$((i + 1))
	done
	port=$(cat "$work/port") &&
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	wait "$server" &&
	python3 - "$work/stdout" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
assert "tpm" in doc
assert "tamper_attempts" in doc
PY
'

test_expect_success 'status --otel without an endpoint does not send' '
	work=$(mktemp -d)
	env -u OTEL_EXPORTER_OTLP_LOGS_ENDPOINT \
		-u OTEL_EXPORTER_OTLP_ENDPOINT \
		"$S" status --json --otel >"$work/stdout" 2>"$work/stderr" &&
	python3 - "$work/stdout" <<"PY"
import json
import sys

doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 1
assert "status" in doc
PY
	rm -rf "$work"
'

test_expect_success 'status --json --include-system includes kernel config' '
	work=$(mktemp -d) &&
	"$S" status --json --include-system >"$work/status.json" 2>"$work/stderr" &&
	cat >"$work/check.py" <<"PY" &&
import json
import os
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
system = doc["system"]
assert isinstance(system["kernel_build_id"], str)
assert all(c in "0123456789abcdef" for c in system["kernel_build_id"])
config = system["kernel_config"]
assert isinstance(config, dict)
assert all(key.startswith("CONFIG_") for key in config)
assert list(config) == sorted(config)

path = "/boot/config-" + system["kernel_release"]
if os.path.isfile(path):
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2:].split(" is not set", 1)[0]
            assert config[key] == "n"
            continue
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if len(value) >= 2 and value[0] == value[-1] == "\"":
                value = value[1:-1]
            assert config[key] == value
            break
    else:
        raise AssertionError("kernel config has no CONFIG_ entries")
PY
	python3 -I "$work/check.py" "$work/status.json" &&
	rm -rf "$work"
'

test_expect_success 'status --include-system prints kernel config' '
	work=$(mktemp -d) &&
	"$S" status --include-system >"$work/status" 2>"$work/stderr" &&
	grep -q "^  Kernel Config:$" "$work/status" &&
	grep -Eq "^  Kernel Build ID: ([0-9a-f]+)?$" "$work/status" &&
	grep -Eq "^    (CONFIG_[^=]+=.*|\\(unavailable\\))$" "$work/status" &&
	rm -rf "$work"
'

test_done
