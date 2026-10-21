#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ../test-lib.sh

H=../helper/test-otel-map
S=../../shirudo

test_expect_success 'OTLP CLI options reject invalid combinations early' '
	! "$S" upatch map --otel-retries=11 >/dev/null 2>&1 &&
	! "$S" upatch map --otel-insecure >/dev/null 2>&1 &&
	! "$S" upatch map --otel=log --metric-kind=gauge >/dev/null 2>&1 &&
	! "$S" upatch map --otel=s3 --metric-kind=gauge >/dev/null 2>&1 &&
	! "$S" upatch map --otel=s3 >/dev/null 2>&1 &&
	! "$S" upatch map --otel=log --s3-uri=s3://bucket >/dev/null 2>&1 &&
	! "$S" upatch map --all unexpected >/dev/null 2>&1 &&
	! "$S" upatch map --all --otel --metric-name=shared \
		>/dev/null 2>&1 &&
	! "$S" upatch map --tenant-id=tenant-uuid-1234 \
		>/dev/null 2>&1 &&
	! "$S" upatch map --otel=log --tenant-id="bad tenant" \
		>/dev/null 2>&1 &&
	! "$S" upatch map --otel=log --tenant-id=one --tenant-id=two \
		>/dev/null 2>&1 &&
	! "$S" upatch map --emit=otel >/dev/null 2>&1
'

test_expect_success 'explicit OTEL modes and JSON combination reach map read' '
	"$S" upatch map missing values \
		--json=combined.ndjson --otel=log \
		--tenant-id=tenant-uuid-1234 \
		--otel-endpoint=http://127.0.0.1:4318 >/dev/null 2>&1;
	test $? -eq 1 && test ! -e combined.ndjson &&
	"$S" upatch map missing values --otel=s3 \
		--s3-uri=s3://test-bucket/prefix >/dev/null 2>&1;
	test $? -eq 1
'

test_expect_success 'automatic OTLP signal classification is structural' '
	case "$($H classify-unsigned)" in metric:*) :;; *) false;; esac &&
	case "$($H classify-hash)" in metric:*) :;; *) false;; esac &&
	case "$($H classify-lru-hash)" in metric:*) :;; *) false;; esac &&
	case "$($H classify-signed)" in log:*) :;; *) false;; esac &&
	case "$($H classify-array)" in log:*) :;; *) false;; esac &&
	case "$($H classify-no-btf)" in log:*) :;; *) false;; esac &&
	case "$($H classify-serialized)" in log:*) :;; *) false;; esac
'

test_expect_success 'local JSON also honors aligned per-CPU strides' '
	"$H" local-json | python3 -c '\''
import json,sys
d=json.load(sys.stdin)
entry=d["entries"][0]
assert entry["values_per_cpu"] == ["5", "7"]
assert entry["sum"] == "12"
'\''
'

test_expect_success 'structured OTLP log preserves aligned per-CPU values' '
	"$H" log | python3 -c '\''
import json,sys
d=json.load(sys.stdin)
r=d["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
vals=r["body"]["kvlistValue"]["values"]
root={x["key"]:x["value"] for x in vals}
data={x["key"]:x["value"] for x in root["data"]["kvlistValue"]["values"]}
entry=data["entries"]["arrayValue"]["values"][0]["kvlistValue"]["values"]
entry={x["key"]:x["value"] for x in entry}
assert [x["stringValue"] for x in entry["values_per_cpu"]["arrayValue"]["values"]] == ["5", "7"]
assert entry["sum"]["stringValue"] == "12"
attrs={x["key"]:x["value"] for x in r["attributes"]}
assert attrs["shirudo.upatch.name"]["stringValue"] == "test-upatch"
assert attrs["shirudo.upatch.location"]["stringValue"] == "fentry/test_hook"
assert attrs["shirudo.map.name"]["stringValue"] == "hits_total"
'\''
'

test_expect_success 'OTLP log tolerates an unavailable upatch location' '
	"$H" log-no-location | python3 -c '\''
import json,sys
d=json.load(sys.stdin)
r=d["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
attrs={x["key"]:x["value"] for x in r["attributes"]}
assert attrs["shirudo.upatch.location"]["stringValue"] == ""
'\''
'

test_expect_success 'OTLP metric emits one aggregated gauge point' '
	"$H" metric | python3 -c '\''
import json,sys
d=json.load(sys.stdin)
m=d["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]
assert m["name"] == "shirudo.test.hits"
p=m["gauge"]["dataPoints"][0]
assert p["asInt"] == "12"
assert "startTimeUnixNano" not in p
'\''
'

test_expect_success 'OTLP counter is cumulative, monotonic, and carries map lifetime' '
	"$H" counter | python3 -c '\''
import json,sys
d=json.load(sys.stdin)
s=d["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]
assert s["aggregationTemporality"] == 2 and s["isMonotonic"] is True
p=s["dataPoints"][0]
assert p["asInt"] == "12"
assert p["startTimeUnixNano"] == "1544712660300000000"
'\''
'

test_expect_success 'OTLP base URL always appends the selected signal path' '
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py success otel.port otel.body otel.meta &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	"$H" send-auto-log "http://127.0.0.1:$port/base" &&
	wait $server &&
	grep -q "\"path\": \"/base/v1/logs\"" otel.meta &&
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py success otel.port otel.body otel.meta &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	"$H" send-auto-metric "http://127.0.0.1:$port/base" &&
	wait $server &&
	python3 -c '\''
import json
assert json.load(open("otel.meta"))["path"] == "/base/v1/metrics"
d=json.load(open("otel.body"))
assert d["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["sum"]["dataPoints"][0]["asInt"] == "12"
'\'' &&
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py success otel.port otel.body otel.meta &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	"$H" send-metric "http://127.0.0.1:$port/custom" &&
	wait $server &&
	python3 -c '\''
import json
assert json.load(open("otel.meta"))["path"] == "/custom/v1/metrics"
d=json.load(open("otel.body"))
assert d["resourceMetrics"][0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0]["asInt"] == "12"
'\''
'

test_expect_success 'remote cleartext requires explicit insecure override' '
	"$H" security
'

test_expect_success '--otel=s3 validates credentials, destinations, and complete views' '
	"$H" s3-validation
'

test_expect_success 'tenant IDs are validated after OTEL header decoding' '
	"$H" tenant-validation
'

test_expect_success 'OTLP HTTP sends JSON, auth headers, gzip, and retries' '
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py retry otel.port otel.body otel.meta &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	OTEL_EXPORTER_OTLP_LOGS_HEADERS="Authorization=Bearer%20secret" \
	OTEL_EXPORTER_OTLP_LOGS_COMPRESSION=gzip \
		"$H" send-log "http://127.0.0.1:$port" 3 &&
	wait $server &&
	python3 -c '\''
import json
json.load(open("otel.body"))
m=json.load(open("otel.meta"))
assert m == {"attempts":3,"path":"/v1/logs","authorization":"Bearer secret","content_encoding":"gzip"}
'\''
'

test_expect_success 'OTLP partial success is a non-retryable failure' '
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py partial otel.port otel.body otel.meta &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	! "$H" send-log "http://127.0.0.1:$port" 3 &&
	wait $server &&
	python3 -c '\''
import json
m=json.load(open("otel.meta"))
assert m["attempts"] == 1
'\''
'

test_expect_success 'HTTPS verifies by default and --otel-insecure disables verification noisily' '
	command -v openssl >/dev/null || exit 0;
	# The exporter only speaks TLS 1.3 with a hybrid ML-KEM group, which
	# the mock server can offer only on an OpenSSL >= 3.5.
	python3 -c "import ssl, sys; sys.exit(0 if ssl.OPENSSL_VERSION_INFO >= (3, 5) else 1)" || exit 0;
	rm -f otel.crt otel.key otel.port otel.body otel.meta otel-tls.err;
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-subj /CN=localhost -addext subjectAltName=DNS:localhost \
		-keyout otel.key -out otel.crt >/dev/null 2>&1;
	python3 ../helper/otel-mock.py success otel.port otel.body otel.meta otel.crt otel.key &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE=otel.crt \
		"$H" send-log "https://localhost:$port" 0 &&
	wait $server &&
	rm -f otel.port otel.body otel.meta;
	python3 ../helper/otel-mock.py success otel.port otel.body otel.meta otel.crt otel.key &
	server=$!;
	i=0; while test ! -s otel.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat otel.port) &&
	"$H" send-log-insecure "https://127.0.0.1:$port" 0 \
		2>otel-tls.err &&
	wait $server &&
	grep -q "disables TLS certificate and hostname verification" otel-tls.err
'

test_expect_success '--otel=s3 uploads gzip JSON then emits a small reference event' '
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py success s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret \
	AWS_SESSION_TOKEN=session AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
	OTEL_EXPORTER_OTLP_LOGS_HEADERS="X-Tenant-ID=ignored-env-tenant" \
		"$H" send-s3 "http://127.0.0.1:$port" 0 &&
	wait $server &&
	python3 -c '\''
import base64,gzip,hashlib,json
raw=open("s3.snapshot","rb").read()
snap=json.loads(gzip.decompress(raw))
assert snap["schema"] == 1 and snap["upatch"] == "test-upatch"
assert snap["map"] == "hits_total" and snap["data"]["truncated"] is False
meta=json.load(open("s3.meta")); put,post=meta["requests"]
digest=hashlib.sha256(raw).hexdigest()
assert put["method"] == "PUT" and put["path"].endswith(digest+".json.gz")
assert put["authorization"].startswith("AWS4-HMAC-SHA256 Credential=test/")
assert put["sigv4_valid"] is True
assert put["content_encoding"] == "gzip" and put["content_type"] == "application/json"
assert put["if_none_match"] == "*" and put["cache_control"] == "immutable"
assert put["content_sha256"] == digest
assert put["checksum_sha256"] == base64.b64encode(hashlib.sha256(raw).digest()).decode()
assert put["security_token"] == "session"
assert put["tenant_id"] == ""
assert post == {"method":"POST","path":"/v1/logs","content_encoding":"","tenant_id":"tenant-uuid-1234"}
log=json.load(open("s3.log"))
record=log["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
assert record["eventName"] == "shirudo.bpf.map.snapshot.reference"
assert set(record["body"]) == {"stringValue"}
attrs={x["key"]:x["value"] for x in record["attributes"]}
assert attrs["shirudo.upatch.name"]["stringValue"] == "test-upatch"
assert attrs["shirudo.upatch.location"]["stringValue"] == "fentry/test_hook"
assert attrs["shirudo.map.name"]["stringValue"] == "hits_total"
uri=attrs["shirudo.map.snapshot.uri"]["stringValue"]
assert uri.startswith("s3://test-bucket/prefix/") and uri.endswith(digest+".json.gz")
assert attrs["shirudo.map.snapshot.sha256"]["stringValue"] == digest
assert len(open("s3.log","rb").read()) < 16384
'\''
'

test_expect_success '--otel=s3 streams snapshots larger than the configured OTLP limit' '
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py success s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
	OTEL_EXPORTER_OTLP_LOGS_HEADERS="X-Tenant-ID=tenant-env-5678" \
		"$H" send-s3-large "http://127.0.0.1:$port" 0 &&
	wait $server &&
	python3 -c '\''
import gzip,json
body=gzip.decompress(open("s3.snapshot","rb").read())
assert len(body) > 1024
d=json.loads(body)
assert d["data"]["serialized"] is True
assert d["data"]["serialized_pages"] == 1
meta=json.load(open("s3.meta")); put,post=meta["requests"]
assert put["tenant_id"] == "" and post["tenant_id"] == "tenant-env-5678"
assert len(open("s3.log","rb").read()) < 16384
'\''
'

test_expect_success '--otel=s3 retries PUT and accepts a content-addressed duplicate' '
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py s3-retry s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$H" send-s3 "http://127.0.0.1:$port" 1 &&
	wait $server &&
	python3 -c '\''
import json
m=json.load(open("s3.meta"))
puts=[r for r in m["requests"] if r["method"] == "PUT"]
assert m["put_attempts"] == 2 and puts[0]["path"] == puts[1]["path"]
'\'' &&
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py exists s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$H" send-s3 "http://127.0.0.1:$port" 0 &&
	wait $server && test -s s3.log
'

test_expect_success '--otel=s3 preserves upload-before-reference failure ordering' '
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py s3-fail s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$H" send-s3 "http://127.0.0.1:$port" 0 2>s3-fail.err &&
	wait $server && test ! -e s3.log && ! grep -q secret s3-fail.err &&
	rm -f s3.port s3.snapshot s3.log s3.meta;
	python3 ../helper/otel-s3-mock.py otel-fail s3.port s3.snapshot s3.log s3.meta &
	server=$!;
	i=0; while test ! -s s3.port && test $i -lt 50; do i=$((i+1)); sleep .02; done &&
	port=$(cat s3.port) &&
	! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=secret AWS_REGION=us-east-1 \
	OTEL_EXPORTER_OTLP_LOGS_ENDPOINT="http://127.0.0.1:$port/v1/logs" \
		"$H" send-s3 "http://127.0.0.1:$port" 0 &&
	wait $server && test -s s3.snapshot && test -s s3.log
'

rm -f otel.port otel.body otel.meta otel-security.err otel-tls.err otel.crt otel.key \
	s3.port s3.snapshot s3.log s3.meta combined.ndjson
rm -f s3-security.err s3-fail.err
test_done
