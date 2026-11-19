#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# testing/end2end/host.sh -- the runner of the end-to-end test. It starts the
# registry, the collectors and the keepalive backend, and boots the operator
# VM, which runs this script again with its name once it is ready; in that
# run the operator publishes, node A runs its tests with node B, a second
# target with a TPM of its own, booting beside it, and the operator verifies
# what node A attests, each step over SSH. Then the runner checks the
# collector and node B. A fresh edge node boots in node A's place and t9109,
# t9110 and t9112 run here against it and node B. A second fresh edge node
# and node B then take their place, on a registry that holds no tree, and
# t9111 runs against them.

set -eu

cd "$(dirname "$0")/../.."
REPO=$PWD
: "${TEST_VM_HOST_BUNDLE:?the test VM bundle is required}"
HOST_PRIVATE_DIR="${TEST_VM_HOST_PRIVATE_DIR:-/tmp/shirudo-test-vm-private-$(id -u)}"
KEYS=$HOST_PRIVATE_DIR/operator-keys/keys
W=$REPO/build/test-vm/end2end
TLS_DIR=$HOST_PRIVATE_DIR/end2end-tls
# The operator's SSH key and disk, which holds its own key, stay out of the
# checkout, which the target VMs mount, or a target could log in to the
# operator and read the signing key.
OPERATOR_PRIVATE_DIR=$HOST_PRIVATE_DIR/end2end-operator
REGISTRY=127.0.0.1:15443
COLLECTOR=127.0.0.1:14318
CLICKHOUSE=127.0.0.1:18123
BACKEND_COLLECTOR=127.0.0.1:14320
BACKEND_CLICKHOUSE=127.0.0.1:18125
. "$REPO/testing/vm/stack-lib.sh"
STACK_NAME=shirudo-end2end
STACK_PERSIST=0
S=$REPO/shirudo
BACKEND=$REPO/tools/backend
export SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build"
export BPM_OCI_CA_FILE="$W/ca.pem"
MAKE=${MAKE:-make}
E2E_VM=${E2E_VM:-${VM_NAME:-end2end-$$}}
export E2E_VM
RESULT=$REPO/build/test-vm/vms/$E2E_VM-end2end/result/end2end
BEE=$W/pkg/kernel-obs-1.0.0.bee
OPERATOR_SH=/workspace/shirudo/testing/end2end/operator.sh
OPERATOR_OUT=/mnt/shirudo-out/end2end
CHECKER=$REPO/tools/quote-check/shirudo-quote-check
KEEPALIVE=$REPO/testing/fixtures/keepalive
NODES_DIR=$W
NODES_HOST=127.0.0.1
NODE_B_PID=
NODE_EDGE_PID=
# The second pair of nodes adds NODE_ROUND to the VM name of the nodes
# beside node A and to their boot logs.
NODE_ROUND=
. "$REPO/testing/end2end/node-lib.sh"

say() { printf 'end2end: %s\n' "$*"; }
die() { printf 'end2end: %s\n' "$*" >&2; exit 1; }

down() {
	node_down edge "$NODE_EDGE_PID"
	NODE_EDGE_PID=
	node_down b "$NODE_B_PID"
	NODE_B_PID=
	stack_down
	rm -rf -- "$TLS_DIR" "$OPERATOR_PRIVATE_DIR"
	rm -f -- "$W/backend-tree.digest"
}

# A command in the operator VM, over SSH.
operator() {
	VM_NAME=$OPERATOR_VM VM_SSH_COMMAND="$*" "$REPO/testing/vm/run.sh" --ssh
}

# The state directory of node $1's VM.
node_run_dir() {
	printf '%s/build/test-vm/vms/%s%s-end2end-%s\n' "$REPO" "$E2E_VM" \
		"$NODE_ROUND" "$1"
}

# Boot node $1, b with the core role or edge with the edge role, prepared
# like node A but without tests, and record in $NODES_DIR/node-$1 how to
# reach it, the key names its vTPM's builder recorded before it booted and
# the CA of its vTPM's endorsement certificate.
node_boot() {
	run=$(node_run_dir "$1")
	mkdir -p "$NODES_DIR/node-$1"
	if "${MAKE:-make}" -C "$REPO/testing" vm-node-end2end END2END_NODE="$1" \
		VM_NAME="$E2E_VM$NODE_ROUND" \
		TEST_VM_CPUS=2 TEST_VM_MEMORY="${TEST_VM_NODE_MEMORY:-2G}" \
		>"$W/node-$1$NODE_ROUND.log" 2>&1 &&
	   cp "$run/ssh.port" "$NODES_DIR/node-$1/port" &&
	   cp "$run/tpm-names" "$NODES_DIR/node-$1/tpm-names" &&
	   cp "$run/enroll.json" "$NODES_DIR/node-$1/enroll.json" &&
	   cp "$run/ek-ca.pem" "$NODES_DIR/node-$1/ek-ca.pem" &&
	   install -m 0600 "$run/ssh/id_ed25519" "$NODES_DIR/node-$1/key"; then
		: >"$NODES_DIR/node-$1/ready"
	else
		: >"$NODES_DIR/node-$1/failed"
	fi
}

# Stop node $1, whose boot runs as process $2 if it is still under way. A
# boot under way ends when its VM stops, or comes up after the first stop
# and meets the second.
node_down() {
	node_stop "$1"
	[ -z "$2" ] || wait "$2" || :
	node_stop "$1"
}

node_stop() {
	[ ! -d "$(node_run_dir "$1")" ] ||
		VM_NAME=$E2E_VM$NODE_ROUND-end2end-$1 "$REPO/testing/vm/run.sh" --stop \
			>/dev/null 2>&1 || :
}

# Print the memory node $1 used, and remove the disks of its stopped VM.
node_clean() {
	run=$(node_run_dir "$1")
	for report in boot-memory host-memory; do
		[ ! -s "$run/result/$report" ] ||
			say "node $1 $report: $(tr '\n' ' ' <"$run/result/$report")"
	done
	rm -rf -- "$run/rootfs.qcow2" "$run/initrd.img" "$run/seed.img" \
		"$run/initrd-seed"
}

# Check the keepalive body that node $1 printed at boot, file $2: the image
# it names is the one the os-release of the end-to-end nodes declares, with
# no root, and with $3 set, its config root is $3.
image_identity() {
	python3 - "$2" "$REPO/testing/vm/files/end2end.os-release" "${3-}" <<'PY' ||
import json, sys

body, release, config_root = sys.argv[1:4]
image = dict(line.split("=", 1) for line in open(release).read().splitlines()
             if "=" in line and not line.startswith("#"))
node = json.load(open(body))
assert node["image_id"] == image["IMAGE_ID"], node["image_id"]
assert node["image_version"] == image["IMAGE_VERSION"], node["image_version"]
assert node["image_root"] is None, node["image_root"]
assert not config_root or node["config_root"] == config_root, node["config_root"]
PY
		die "node $1 does not declare the image of the end-to-end nodes"
}

# Run the test end2end/$1.sh on the host against the fresh edge node and
# node B, with the keepalive backend, into $W/<number>.log. t9110 continues
# what t9109 left in both nodes and the tree, so they run in that order.
host_test() {
	log=$W/${1%%-*}.log
	say "${1%%-*}, on the host, against the fresh edge node and node B"
	rc=0
	(cd testing && E2E=$W END2END_BACKEND=$BACKEND END2END_KEYS=$KEYS \
		NODES_DIR=$NODES_DIR NODES_HOST=$NODES_HOST \
		sh "end2end/$1.sh") >"$log" 2>&1 || rc=$?
	cat "$log"
	[ "$rc" -eq 0 ] || die "${1%%-*} failed; see $log"
	! grep -q '^1\.\.0 # SKIP' "$log" || die "${1%%-*} was skipped"
}

# Boot the second pair of nodes for t9111, a fresh edge node and a fresh
# node B with TPMs of their own, once the first pair has stopped, so that
# two guests run at most. Their config images name the tree t9109 and
# t9110 grew, so the registry starts again without it, and holds no tree.
second_pair() {
	NODE_ROUND=-2
	rm -rf -- "$NODES_DIR/node-edge" "$NODES_DIR/node-b"
	docker rm -fv "$STACK_NAME-registry" >/dev/null 2>&1 || :
	stack_oci || die "the registry did not come up again"
	say "a second fresh edge node and node B, in $E2E_VM$NODE_ROUND-end2end-edge and -b"
	node_boot edge &
	NODE_EDGE_PID=$!
	node_boot b &
	NODE_B_PID=$!
	wait "$NODE_EDGE_PID" || :
	wait "$NODE_B_PID" || :
	NODE_EDGE_PID=
	NODE_B_PID=
	for n in edge b; do
		node_wait "$n" 0 || {
			tail -n 40 "$W/node-$n$NODE_ROUND.log" >&2
			die "node $n of the second pair did not boot; see $W/node-$n$NODE_ROUND.log"
		}
	done
	[ "$(node_sh edge cat /run/shirudo/config/etc/shirudo/node.labels)" = role=edge ] &&
	[ "$(node_sh b cat /run/shirudo/config/etc/shirudo/node.labels)" = role=core ] ||
		die "the second pair is not labelled role=edge and role=core"
}

# Publish the example tree of the keepalive fixtures, signed with the
# operator key, at oci://$REGISTRY/$1:stable. Its operations name
# artifacts that do not exist, so bpm tree append cannot write it: the
# document and its signature take the place of those of a publication
# append made. Prints the manifest digest.
publish_document() {
	"$S" bpm tree append "$BEE" "oci://$REGISTRY/$1" --keys-dir "$KEYS" \
		>/dev/null &&
	openssl cms -sign -binary -md sha512 -in "$KEEPALIVE/tree-1.1.0.json" \
		-signer "$KEYS/cert.der" -inkey "$KEYS/signing_key.pem" \
		-outform DER -out "$W/tree-1.1.0.sig" -nosmimecap -nocerts -keyid &&
	python3 - "$REGISTRY" "$W/ca.pem" "$1" "$KEEPALIVE/tree-1.1.0.json" \
		"$W/tree-1.1.0.sig" <<'PY'
import hashlib, json, ssl, sys, urllib.request

registry, ca, repository, document, signature = sys.argv[1:6]
ctx = ssl.create_default_context(cafile=ca)
base = f"https://{registry}/v2/{repository}"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
LAYERS = {"application/vnd.shirudo.upatch.tree.v1+json": document,
          "application/vnd.shirudo.upatch.tree.signature.v1": signature}


def call(method, url, body=None, headers=None):
    request = urllib.request.Request(url, data=body, method=method,
                                     headers=headers or {})
    return urllib.request.urlopen(request, context=ctx)


def push(body):
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    with call("POST", f"{base}/blobs/uploads/") as response:
        location = response.headers["Location"]
    if location.startswith("/"):
        location = f"https://{registry}{location}"
    separator = "&" if "?" in location else "?"
    call("PUT", f"{location}{separator}digest={digest}", body,
         {"Content-Type": "application/octet-stream"}).close()
    return digest


with call("GET", f"{base}/manifests/stable", headers={"Accept": MANIFEST}) as r:
    manifest = json.load(r)
for layer in manifest["layers"]:
    body = open(LAYERS[layer["mediaType"]], "rb").read()
    layer["digest"] = push(body)
    layer["size"] = len(body)
raw = json.dumps(manifest, separators=(",", ":")).encode()
call("PUT", f"{base}/manifests/stable", raw,
     {"Content-Type": manifest.get("mediaType", MANIFEST)}).close()
print("sha256:" + hashlib.sha256(raw).hexdigest())
PY
}

# The operator VM serves this, with its own name as the argument.
if [ $# -eq 1 ]; then
	OPERATOR_VM=$1
	say "the operator builds, pushes and publishes kernel-obs"
	operator "$OPERATOR_SH" publish
	operator cat "$OPERATOR_OUT/nonce" >"$W/nonce"
	say "the keepalive backend of tools/backend loads the example tree"
	operator cat "$OPERATOR_OUT/pkg/kernel-obs-1.0.0.bee" >"$BEE"
	publish_document shirudo/fleet-base >"$W/backend-tree.digest" ||
		die "cannot publish the example tree"
	CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client" \
		SHIRUDO="$S" "$BACKEND/jobs/tree-ingest" --cert "$KEYS/cert.der" \
		"oci://$REGISTRY/shirudo/fleet-base" >"$W/tree-ingest.out" 2>&1 || {
		cat "$W/tree-ingest.out" >&2
		rm -f "$W/backend-tree.digest"
		die "the tree ingest job did not load the example tree"
	}
	# Node B outlives this run, which ends with its boot over, or with it
	# stopped when the run fails.
	trap '[ $? -eq 0 ] || node_down b "$NODE_B_PID"' EXIT
	say "node A, in $E2E_VM-end2end, and node B, in $E2E_VM-end2end-b"
	node_boot b &
	NODE_B_PID=$!
	"$MAKE" -C "$REPO/testing" vm-test-end2end VM_NAME="$E2E_VM"
	say "the operator verifies the evidence and records node A returned"
	[ -s "$RESULT/evidence.json" ] || die "node A left no evidence in $RESULT"
	operator "cat >$OPERATOR_OUT/evidence.json" <"$RESULT/evidence.json"
	operator "$OPERATOR_SH" verify
	wait "$NODE_B_PID" || :
	exit 0
fi
[ $# -eq 0 ] || die "usage: $0"

command -v docker >/dev/null 2>&1 || die "docker is required"
[ -x "$CHECKER" ] || die "no quote checker: $CHECKER; run make quote-check"
private_dir="$(realpath -m "$HOST_PRIVATE_DIR")"
repo_dir="$(realpath -m "$REPO")"
[ "$private_dir" != "$repo_dir" ] &&
	[ "${private_dir#"$repo_dir"/}" = "$private_dir" ] ||
	die "TEST_VM_HOST_PRIVATE_DIR must be outside the repository"
install -d -m 0700 "$HOST_PRIVATE_DIR"
chmod 0700 "$HOST_PRIVATE_DIR"
[ -s "$KEYS/signing_key.pem" ] || die "no host-only operator key: $KEYS"
rm -rf "$W"
mkdir -p "$W/out" "$W/pkg"
chmod 0777 "$W/out"
down
install -d -m 0755 "$TLS_DIR"
trap down EXIT

stack_prepare
say "the registry, collector and ClickHouse"
stack_oci || die "the registry did not come up"
stack_telemetry || die "the telemetry stack did not come up"

say "the keepalive backend of tools/backend"
stack_backend "$BACKEND" "$CHECKER" ||
	die "the keepalive backend did not come up"

say "the operator, in $E2E_VM-operator"
# Each VM's name goes on make's command line, where a VM_NAME the caller
# gave make reaches every sub-make and overrides the environment.
TEST_VM_SERVE_COMMAND="$REPO/testing/end2end/host.sh" \
	TEST_VM_PRIVATE_DIR="$OPERATOR_PRIVATE_DIR" \
	"$MAKE" -C "$REPO/testing" vm-operator-end2end \
	VM_NAME="$E2E_VM-operator"

# The fresh edge node takes the place of node A and the operator, so that
# two guests run at most.
say "the fresh edge node, in $E2E_VM-end2end-edge"
node_boot edge &
NODE_EDGE_PID=$!

say "the collector holds what kernel-obs observed"
python3 "$REPO/testing/end2end/check-otlp.py" "$RESULT/otel" \
	"$W/out/otlp.json" "http://$CLICKHOUSE/" || \
	die "the collector or ClickHouse snapshots differ from the map exports"

say "node B booted with an attestation key and a role of its own"
node_wait b 0 || {
	tail -n 40 "$W/node-b.log" >&2
	die "node B did not boot; see $W/node-b.log"
}
ak=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["ak"]["name"])' \
	"$RESULT/evidence.json")
node_sh b "/usr/local/bin/shirudo-runtime attest --nonce=$(cat "$W/nonce")" \
	>"$W/node-b-evidence.json" || die "node B gave no evidence"
# Node B loads nothing of its own: a test gives it only what a tree holds.
python3 -c 'import json, sys
evidence = json.load(open(sys.argv[1]))
assert not [r for r in evidence["eventlog"] if r["type"] == "upatch_load"]' \
	"$W/node-b-evidence.json" ||
	die "node B loaded an upatch while it was prepared"
# The names come from the builder, never from the node.
ak_b=$(node_builder_name b ak)
ek_b=$(node_builder_name b ek)
"$S" attest verify --evidence="$W/node-b-evidence.json" \
	--nonce="$(cat "$W/nonce")" --ak-name="$ak_b" --ek-name="$ek_b" \
	--allow-runtime-events --require-initrd >"$W/node-b-verify.out" 2>&1 &&
	grep -qx 'verdict: ok' "$W/node-b-verify.out" || {
	cat "$W/node-b-verify.out" >&2
	die "the evidence of node B does not verify against its builder's names"
}
! "$S" attest verify --evidence="$W/node-b-evidence.json" \
	--nonce="$(cat "$W/nonce")" --ak-name="$ak" --ek-name="$ek_b" \
	--allow-runtime-events --require-initrd >"$W/node-b-wrong.out" 2>&1 &&
	grep -qx '  FAIL  attestation key: the pinned key' "$W/node-b-wrong.out" || {
	cat "$W/node-b-wrong.out" >&2
	die "the evidence of node B is not refused for node A's attestation key"
}
[ "$ak_b" != "$ak" ] || die "node A and node B share an attestation key"
[ "$(node_sh b cat /run/shirudo/config/etc/shirudo/node.labels)" = role=core ] ||
	die "node B is not labelled role=core"
image_identity A "$REPO/build/test-vm/vms/$E2E_VM-end2end/result/keepalive.json"
image_identity B "$(node_run_dir b)/result/keepalive.json" \
	"$(cat "$TEST_VM_HOST_BUNDLE/verity/config-core.root")"

wait "$NODE_EDGE_PID" || :
NODE_EDGE_PID=
node_wait edge 0 || {
	tail -n 40 "$W/node-edge.log" >&2
	die "the fresh edge node did not boot; see $W/node-edge.log"
}
[ "$(node_sh edge cat /run/shirudo/config/etc/shirudo/node.labels)" = role=edge ] ||
	die "the fresh edge node is not labelled role=edge"
image_identity edge "$(node_run_dir edge)/result/keepalive.json" \
	"$(cat "$TEST_VM_HOST_BUNDLE/verity/config-edge.root")"
host_test t9109-pipeline
host_test t9110-keepalive-history
host_test t9112-activation
node_down edge ""
node_clean edge
node_down b ""
node_clean b
second_pair
host_test t9111-pipeline-segments
node_down edge ""
node_clean edge
node_down b ""
node_clean b

say "ok"
