#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# testing/end2end/operator.sh publish|verify -- the operator's side of the
# end-to-end test, run over SSH in the operator VM with the operator package
# and the signing key: publish what the target loads and the nonce it attests
# with, then verify the evidence it returned against what was published.

set -eu

cd "$(dirname "$0")/../.."
REPO=$PWD
KEYS=/mnt/shirudo-operator-keys
W=/mnt/shirudo-out/end2end
REGISTRY=registry.test:15443
POLICY_FIXTURE=/mnt/shirudo-bundle/fixtures/shirudo-test-policy-exec-graph.upatch
export BPM_OCI_CA_FILE="$REPO/build/test-vm/end2end/ca.pem"

say() { printf 'end2end operator: %s\n' "$*"; }
die() { printf 'end2end operator: %s\n' "$*" >&2; exit 1; }

payload() {
	shirudo upatch info --json "$1" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])'
}

# The Java agent e2e-java, compiled here as an operator would, packaged,
# pushed and appended to the tree after kernel-obs, for the same nodes.
publish_java() {
	java=$W/java
	mkdir -p "$java/classes" "$W/pkg/e2e-java"
	say "compile the Java agent e2e-java and sign it into a package"
	javac --release 11 -d "$java/classes" \
		"$REPO/testing/end2end/java-agent/Agent.java"
	printf 'Premain-Class: shirudo.e2e.Agent\n' >"$java/manifest"
	jar --create --file "$W/pkg/e2e-java/e2e-java.jar" \
		--manifest "$java/manifest" -C "$java/classes" .
	cat >"$W/pkg/e2e-java/Beefile" <<-'EOF'
	[package]
	name = "e2e-java"
	description = "The Java agent of the end-to-end test"

	[[upatches]]
	source = "e2e-java.jar"
	type = "java"

	[upatches.tree]
	id = "e2e-java"

	[upatches.tree.selector.labels]
	role = ["edge"]
	EOF
	(cd "$W/pkg" && shirudo bpm build e2e-java --version 1.0.0 --keys-dir "$KEYS")
	bee=$W/pkg/e2e-java-1.0.0.bee
	say "push it to oci://$REGISTRY and append it to the upatch tree"
	shirudo bpm push "$bee" "oci://$REGISTRY/shirudo/e2e-java" \
		--keys-dir "$KEYS"
	shirudo bpm tree append "$bee" "oci://$REGISTRY/shirudo/end2end-tree" \
		--keys-dir "$KEYS" --tree-id kernel-obs
	tar --no-same-owner -xzf "$bee" -C "$W/pkg"
	payload "$W/pkg/e2e-java-1.0.0/upatches/e2e-java.upatch" >"$W/java-payload"
}

# The jars of t9113, built here because javac is here: the agent of the
# java-base64 shield, which the host signs into its package, and the
# program that shows whether a JVM runs it.
build_shield_jars() {
	say "build the java-base64 agent and badDecoder"
	"$REPO/upatches/java-base64/build.sh" --jar-only
	"$REPO/upatches/test/build.sh"
	mkdir -p "$W/shield"
	cp "$REPO/upatches/java-base64/java-base64.jar" \
		"$REPO/upatches/test/badDecoder.jar" "$W/shield/"
}

publish() {
	[ -s "$BPM_OCI_CA_FILE" ] || die "no CA of the registry: $BPM_OCI_CA_FILE"
	[ -s "$POLICY_FIXTURE" ] || die "no policy exec graph fixture: $POLICY_FIXTURE"
	rm -rf "$W"
	mkdir -p "$W/pkg"
	cp -R "$REPO/upatches/kernel-obs" "$W/pkg/kernel-obs"
	sed -i '/^source = "kernel-obs.bpf.c"$/a\
\
[upatches.tree]\
id = "kernel-obs"\
\
[upatches.tree.selector.labels]\
role = ["edge"]' "$W/pkg/kernel-obs/Beefile"
	say "build kernel-obs with the installed headers and vmlinux.h"
	(cd "$W/pkg" && shirudo bpm build kernel-obs --version 1.0.0 --keys-dir "$KEYS")
	bee=$W/pkg/kernel-obs-1.0.0.bee
	say "push it to oci://$REGISTRY and append it to the upatch tree"
	shirudo bpm push "$bee" "oci://$REGISTRY/shirudo/kernel-obs" \
		--keys-dir "$KEYS" --new-index
	shirudo bpm tree append "$bee" "oci://$REGISTRY/shirudo/end2end-tree" \
		--keys-dir "$KEYS"
	tar --no-same-owner -xzf "$bee" -C "$W/pkg"
	payload "$W/pkg/kernel-obs-1.0.0/upatches/kernel-obs.upatch" >"$W/payload"
	publish_java
	build_shield_jars
	payload "$POLICY_FIXTURE" >"$W/policy-payload"
	openssl rand -hex 16 >"$W/nonce"
}

verify() {
	[ -s "$W/evidence.json" ] || die "no evidence to verify in $W"
	ak=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["ak"]["name"])' \
		"$W/evidence.json")
	say "verify the evidence"
	shirudo attest verify --evidence="$W/evidence.json" \
		--nonce="$(cat "$W/nonce")" --ak-name="$ak" \
		--allow-runtime-events --require-initrd >"$W/verify.out" 2>&1 || {
		cat "$W/verify.out" >&2
		die "the evidence does not verify"
	}
	grep -qx 'verdict: ok' "$W/verify.out" || die "the evidence does not verify"
	say "the target loaded what was published"
	# The records replay to the register the TPM certified, so the last load
	# and tree operation they name are the target's.
	python3 - "$W/evidence.json" "$(cat "$W/payload")" \
		"$(cat "$W/policy-payload")" "$BPM_OCI_CA_FILE" "$REGISTRY" \
		"$(cat "$W/java-payload")" <<'PY' ||
import json, ssl, sys, urllib.request

evidence, payload, policy_payload, ca, registry, java_payload = sys.argv[1:7]
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
java_loads = [r["upatch"] for r in records if r["type"] == "java_load"]
assert java_loads == [{"name": "e2e-java",
                       "payload_sha256": java_payload}], java_loads
ops = [r["tree"] for r in records if r["type"] == "tree_op"]
assert ops[-1] == {key: published[key] for key in
                   ("seq", "op", "id", "operation_digest")}, (ops[-1], published)
PY
		die "the target did not load what was published"
}

case "${1:-}" in
publish) publish ;;
verify) verify ;;
*)
	printf 'usage: %s publish|verify\n' "$0" >&2
	exit 2
	;;
esac
