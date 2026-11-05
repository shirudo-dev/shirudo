#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# testing/end2end/host.sh -- run the operator side of the end-to-end VM test.

set -eu

cd "$(dirname "$0")/../.."
REPO=$PWD
: "${TEST_VM_HOST_BUNDLE:?the test VM bundle is required}"
HOST_PRIVATE_DIR="${TEST_VM_HOST_PRIVATE_DIR:-/tmp/shirudo-test-vm-private-$(id -u)}"
KEYS=$HOST_PRIVATE_DIR/operator-keys/keys
W=$REPO/build/test-vm/end2end
TLS_DIR=$HOST_PRIVATE_DIR/end2end-tls
REGISTRY=127.0.0.1:15443
COLLECTOR=127.0.0.1:14318
CLICKHOUSE=127.0.0.1:18123
# registry 3.1.2 and opentelemetry-collector-contrib 0.164.0, both built
# with a Go that offers the hybrid ML-KEM group shirudo requires.
REGISTRY_IMAGE=docker.io/library/registry@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3
COLLECTOR_IMAGE=docker.io/otel/opentelemetry-collector-contrib@sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b
CLICKHOUSE_IMAGE=docker.io/clickhouse/clickhouse-server@sha256:d426d2f612e1e189c90f9a3f8dcd85a03c6851273833817a296bb327e63aa7a7
S=$REPO/shirudo
export SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build"
export BPM_OCI_CA_FILE="$W/ca.pem"
VM_NAME=${VM_NAME:-end2end-$$}
export VM_NAME
RESULT=$REPO/build/test-vm/vms/$VM_NAME-end2end/result/end2end
POLICY_FIXTURE=$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-policy-exec-graph.upatch
KSOCK_PID=

say() { printf 'end2end: %s\n' "$*"; }
die() { printf 'end2end: %s\n' "$*" >&2; exit 1; }

down() {
	if [ -n "$KSOCK_PID" ]; then
		kill "$KSOCK_PID" 2>/dev/null || true
		wait "$KSOCK_PID" 2>/dev/null || true
		KSOCK_PID=
	fi
	docker logs shirudo-end2end-collector >"$W/collector.log" 2>&1 || true
	docker logs shirudo-end2end-clickhouse >"$W/clickhouse.log" 2>&1 || true
	docker rm -f shirudo-end2end-registry shirudo-end2end-collector \
		shirudo-end2end-clickhouse \
		>/dev/null 2>&1 || true
	docker network rm shirudo-end2end >/dev/null 2>&1 || true
	rm -rf -- "$TLS_DIR"
}

# Up to ten seconds for a TLS service to answer an HTTP request.
wait_https() {
	i=0
	until curl -fsS --cacert "$W/ca.pem" "$@" >/dev/null 2>&1; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || return 1
		sleep 0.2
	done
}

command -v docker >/dev/null 2>&1 || die "docker is required"
private_dir="$(realpath -m "$HOST_PRIVATE_DIR")"
repo_dir="$(realpath -m "$REPO")"
[ "$private_dir" != "$repo_dir" ] &&
	[ "${private_dir#"$repo_dir"/}" = "$private_dir" ] ||
	die "TEST_VM_HOST_PRIVATE_DIR must be outside the repository"
install -d -m 0700 "$HOST_PRIVATE_DIR"
chmod 0700 "$HOST_PRIVATE_DIR"
[ -s "$KEYS/signing_key.pem" ] || die "no host-only operator key: $KEYS"
[ -s "$POLICY_FIXTURE" ] || die "no policy exec graph fixture: $POLICY_FIXTURE"
rm -rf "$W"
mkdir -p "$W/out" "$W/pkg"
chmod 0777 "$W/out"
down
install -d -m 0755 "$TLS_DIR"
trap down EXIT

say "a CA, and a server certificate for the registry and the collector"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$TLS_DIR/ca.key" -out "$W/ca.pem" -days 1 \
	-subj /CN=shirudo-end2end-ca \
	-addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" \
	-subj /CN=shirudo-end2end 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,IP:10.0.2.2\n' >"$TLS_DIR/server.ext"
openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$W/ca.pem" \
	-CAkey "$TLS_DIR/ca.key" -CAcreateserial -out "$TLS_DIR/server.pem" \
	-days 1 -extfile "$TLS_DIR/server.ext" 2>/dev/null
rm -f -- "$TLS_DIR/ca.key" "$TLS_DIR/server.csr" \
	"$TLS_DIR/server.ext" "$TLS_DIR/ca.srl"
chmod 0644 "$TLS_DIR/server.key"
openssl rand -hex 16 >"$W/nonce"

say "the registry, collector and ClickHouse"
docker network create shirudo-end2end >/dev/null
docker run -d --name shirudo-end2end-clickhouse \
	--network shirudo-end2end --network-alias clickhouse \
	-p "$CLICKHOUSE:8123" -e CLICKHOUSE_SKIP_USER_SETUP=1 \
	"$CLICKHOUSE_IMAGE" >/dev/null
i=0
until curl -fsS --data-binary 'SELECT 1' "http://$CLICKHOUSE/" >/dev/null 2>&1; do
	i=$((i + 1))
	[ "$i" -lt 150 ] || die "ClickHouse did not come up"
	sleep 0.2
done
docker run -d --name shirudo-end2end-registry -p "$REGISTRY:5000" \
	-v "$TLS_DIR:/certs:ro" -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.pem \
	-e REGISTRY_HTTP_TLS_KEY=/certs/server.key "$REGISTRY_IMAGE" >/dev/null
docker run -d --name shirudo-end2end-collector -p "$COLLECTOR:4318" \
	--network shirudo-end2end \
	-v "$TLS_DIR:/certs:ro" -v "$W/out:/out" \
	-v "$REPO/testing/end2end/otelcol.yaml:/etc/otelcol-contrib/config.yaml:ro" \
	"$COLLECTOR_IMAGE" >/dev/null
wait_https "https://$REGISTRY/v2/" || die "the registry did not come up"
wait_https -X POST -H 'Content-Type: application/json' -d '{}' \
	"https://$COLLECTOR/v1/logs" || die "the collector did not come up"

say "the operator builds, pushes and publishes kernel-obs"
cp -R upatches/kernel-obs "$W/pkg/kernel-obs"
ln -s "$REPO/vendor" "$W/pkg/kernel-obs/vendor"
ln -s "$REPO/bpf" "$W/pkg/kernel-obs/bpf"
sed -i '/^source = "kernel-obs.bpf.c"$/a\
\
[upatches.tree]\
id = "kernel-obs"\
\
[upatches.tree.selector.labels]\
role = ["end2end"]' "$W/pkg/kernel-obs/Beefile"
(cd "$W/pkg" && "$S" bpm build kernel-obs --version 1.0.0 --keys-dir "$KEYS")
BEE=$W/pkg/kernel-obs-1.0.0.bee
"$S" bpm push "$BEE" "oci://$REGISTRY/shirudo/kernel-obs" --keys-dir "$KEYS"
"$S" bpm tree append "$BEE" "oci://$REGISTRY/shirudo/end2end-tree" \
	--keys-dir "$KEYS"
tar -xzf "$BEE" -C "$W/pkg"
"$S" upatch info --json "$W/pkg/kernel-obs-1.0.0/upatches/kernel-obs.upatch" |
	python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])' \
	>"$W/payload"
"$S" upatch info --json "$POLICY_FIXTURE" |
	python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])' \
	>"$W/policy-payload"

say "a host UDP receiver for the signed ksock sender"
python3 "$REPO/testing/end2end/ksock-receiver.py" \
	"$W/ksock-ready" "$W/ksock-received" >"$W/ksock.log" 2>&1 &
KSOCK_PID=$!
i=0
while [ ! -s "$W/ksock-ready" ]; do
	i=$((i + 1))
	if [ "$i" -ge 50 ]; then
		cat "$W/ksock.log" >&2
		die "the ksock UDP receiver did not bind"
	fi
	sleep 0.1
done

say "the target, in $VM_NAME-end2end"
"$@"

say "the host received the datagram sent by the signed ksock upatch"
i=0
while [ ! -s "$W/ksock-received" ]; do
	i=$((i + 1))
	if [ "$i" -ge 50 ]; then
		cat "$W/ksock.log" >&2
		die "the host received no valid ksock datagram"
	fi
	sleep 0.1
done
wait "$KSOCK_PID" || die "the ksock UDP receiver failed"
KSOCK_PID=
printf 'shirudo ksock dummy\n' | cmp - "$W/ksock-received" ||
	die "the ksock payload differs"

say "the evidence verifies and records what was published"
[ -s "$RESULT/evidence.json" ] || die "the target left no evidence in $RESULT"
ak=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["ak"]["name"])' \
	"$RESULT/evidence.json")
"$S" attest verify --evidence="$RESULT/evidence.json" --nonce="$(cat "$W/nonce")" \
	--ak-name="$ak" --allow-runtime-events --require-initrd \
	>"$W/verify.out" 2>&1 || {
	cat "$W/verify.out" >&2
	die "the evidence does not verify"
}
grep -qx 'verdict: ok' "$W/verify.out" || die "the evidence does not verify"
# The records replay to the register the TPM certified, so the last load
# and tree operation they name are the target's.
python3 - "$RESULT/evidence.json" "$(cat "$W/payload")" \
	"$(cat "$W/policy-payload")" "$W/ca.pem" "$REGISTRY" <<'PY' || \
	die "the target did not load what was published"
import json, ssl, sys, urllib.request

evidence, payload, policy_payload, ca, registry = sys.argv[1:6]
ctx = ssl.create_default_context(cafile=ca)


def get(path, accept=None):
    request = urllib.request.Request(f"https://{registry}/v2/{path}")
    if accept:
        request.add_header("Accept", accept)
    return urllib.request.urlopen(request, context=ctx).read()


repo = "shirudo/end2end-tree"
manifest = json.loads(get(f"{repo}/manifests/stable",
                          "application/vnd.oci.image.manifest.v1+json"))
published = None
for layer in manifest["layers"]:
    try:
        document = json.loads(get(f"{repo}/blobs/{layer['digest']}"))
    except ValueError:
        continue
    if isinstance(document, dict) and "operations" in document:
        published = document["operations"][-1]
assert published, "no publication in the tree"
records = json.load(open(evidence))["eventlog"]
loads = [r["upatch"] for r in records if r["type"] == "upatch_load"]
assert {"name": "kernel-obs", "payload_sha256": payload} in loads, loads
assert loads[-1] == {"name": "policy-exec-graph",
                     "payload_sha256": policy_payload}, loads[-1]
ops = [r["tree"] for r in records if r["type"] == "tree_op"]
assert ops[-1] == {key: published[key] for key in
                   ("seq", "op", "id", "operation_digest")}, (ops[-1], published)
PY

say "the collector holds what kernel-obs observed"
python3 "$REPO/testing/end2end/check-otlp.py" \
	"$REPO/build/test-vm/vms/$VM_NAME-end2end/result/end2end/otel" \
	"$W/out/otlp.json" "http://$CLICKHOUSE/" || \
	die "the collector or ClickHouse snapshots differ from the map exports"
python3 - "$W/out/otlp.json" <<'PY' || die "the collector did not get the export"
import json, sys

upatches, text = set(), ""
with open(sys.argv[1]) as f:
    for line in f:
        text += line
        for rl in json.loads(line).get("resourceLogs", []):
            for sl in rl.get("scopeLogs", []):
                for record in sl.get("logRecords", []):
                    for kv in record.get("attributes", []):
                        if kv["key"] == "shirudo.upatch.name":
                            upatches.add(kv["value"].get("stringValue"))
assert "kernel-obs" in upatches, upatches
assert "end2end/exec-paths" in text, "no exec record of the test's program"
PY
say "ok"
