#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/end2end/host.sh <command>... -- the operator's side of the
# end-to-end test, around <command>, which boots the end2end VM. An OCI
# registry and an OpenTelemetry Collector run in containers behind a
# throwaway CA; the operator builds kernel-obs into a package, pushes it
# and appends it to a signed upatch tree. After the VM, the TPM-signed
# evidence the target left must verify and record the published operation
# and payload, and the collector must hold what the package observed.

set -eu

cd "$(dirname "$0")/../.."
REPO=$PWD
: "${TEST_VM_HOST_BUNDLE:?the test VM bundle is required}"
KEYS=$TEST_VM_HOST_BUNDLE.operator/keys
W=$REPO/build/test-vm/end2end
REGISTRY=127.0.0.1:15443
COLLECTOR=127.0.0.1:14318
# registry 3.1.2 and opentelemetry-collector-contrib 0.164.0, both built
# with a Go that offers the hybrid ML-KEM group shirudo requires.
REGISTRY_IMAGE=docker.io/library/registry@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3
COLLECTOR_IMAGE=docker.io/otel/opentelemetry-collector-contrib@sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b
S=$REPO/shirudo
export SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build"
export BPM_OCI_CA_FILE="$W/ca.pem"
VM_NAME=${VM_NAME:-end2end-$$}
export VM_NAME
RESULT=$REPO/build/test-vm/vms/$VM_NAME-end2end/result/end2end
POLICY_FIXTURE=$TEST_VM_HOST_BUNDLE/fixtures/shirudo-test-policy-exec-graph.upatch

say() { printf 'end2end: %s\n' "$*"; }
die() { printf 'end2end: %s\n' "$*" >&2; exit 1; }

down() {
	docker logs shirudo-end2end-collector >"$W/collector.log" 2>&1 || true
	docker rm -f shirudo-end2end-registry shirudo-end2end-collector \
		>/dev/null 2>&1 || true
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
[ -s "$KEYS/signing_key.pem" ] || die "no operator key beside the bundle: $KEYS"
[ -s "$POLICY_FIXTURE" ] || die "no policy exec graph fixture: $POLICY_FIXTURE"
rm -rf "$W"
mkdir -p "$W/out" "$W/pkg"
chmod 0777 "$W/out"
down
trap down EXIT

say "a CA, and a server certificate for the registry and the collector"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$W/ca.key" -out "$W/ca.pem" -days 1 \
	-subj /CN=shirudo-end2end-ca \
	-addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
	-keyout "$W/server.key" -out "$W/server.csr" \
	-subj /CN=shirudo-end2end 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1,IP:10.0.2.2\n' >"$W/server.ext"
openssl x509 -req -in "$W/server.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" \
	-CAcreateserial -out "$W/server.pem" -days 1 \
	-extfile "$W/server.ext" 2>/dev/null
chmod 0644 "$W/server.key"
openssl rand -hex 16 >"$W/nonce"

say "the registry and the collector"
docker run -d --name shirudo-end2end-registry -p "$REGISTRY:5000" \
	-v "$W:/certs:ro" -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.pem \
	-e REGISTRY_HTTP_TLS_KEY=/certs/server.key "$REGISTRY_IMAGE" >/dev/null
docker run -d --name shirudo-end2end-collector -p "$COLLECTOR:4318" \
	-v "$W:/certs:ro" -v "$W/out:/out" \
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

say "the target, in $VM_NAME-end2end"
"$@"

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
