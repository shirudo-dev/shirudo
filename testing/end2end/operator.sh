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
		"$(cat "$W/policy-payload")" "$BPM_OCI_CA_FILE" "$REGISTRY" <<'PY' ||
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
