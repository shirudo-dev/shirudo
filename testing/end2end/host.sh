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
. "$REPO/testing/vm/stack-lib.sh"
STACK_NAME=shirudo-end2end
STACK_PERSIST=0
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
	stack_down
	rm -rf -- "$TLS_DIR"
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

stack_prepare
openssl rand -hex 16 >"$W/nonce"
say "the registry, collector and ClickHouse"
stack_oci || die "the registry did not come up"
stack_telemetry || die "the telemetry stack did not come up"

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
"$S" bpm push "$BEE" "oci://$REGISTRY/shirudo/kernel-obs" --keys-dir "$KEYS" \
	--new-index
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
python3 "$REPO/testing/end2end/check-otlp.py" \
	"$REPO/build/test-vm/vms/$VM_NAME-end2end/result/end2end/otel" \
	"$W/out/otlp.json" "http://$CLICKHOUSE/" || \
	die "the collector or ClickHouse snapshots differ from the map exports"

say "ok"
