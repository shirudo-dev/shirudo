#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7005 -- operator-side publishing without the former Go tool: build a
# .bee package whose Beefile carries [upatches.tree] metadata, push it to
# a local OCI registry while updating the signed repository index, then
# append load and delete operations to a signed upatch tree. The index
# and tree signatures are checked with openssl against the operator cert,
# the documents against the schema the target consumes, and the operation
# digest against an independent recomputation of its canonical form.
# Needs clang, shirudo-build, python3 and an OpenSSL >= 3.5 (ML-DSA).

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h (build the tree)"
openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA' ||
	test_skip_all "openssl without ML-DSA (needs OpenSSL >= 3.5)"

REPO=$(cd .. && pwd)
case "$SHB" in
/*) B="$SHB" ;;
*)  B="$REPO/${SHB#../}" ;;
esac
S="$REPO/shirudo"

WORK=$(mktemp -d)
SERVER_PID=
cleanup() {
	[ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || :
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "genkey failed"
openssl x509 -inform DER -in "$WORK/keys/cert.der" -out "$WORK/cert.pem" 2>/dev/null

# The package directory doubles as shirudo-build's working directory, so
# the vendored headers and vmlinux.h are reached through symlinks.
mkdir -p "$WORK/pkg"
ln -s "$REPO/vendor" "$WORK/pkg/vendor"
ln -s "$REPO/bpf" "$WORK/pkg/bpf"
cat >"$WORK/pkg/t7005.bpf.c" <<'BPF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(t0031_fn)
{
	return 0;
}
BPF
cat >"$WORK/pkg/Beefile" <<'TOML'
[package]
name = "t7005"
description = "publishing test"

[[upatches]]
source = "t7005.bpf.c"

[upatches.tree]
id = "t7005"

[upatches.tree.selector]
architecture = ["x86_64", "aarch64"]
kernel_release_prefix = ["7."]

[upatches.tree.selector.labels]
env = ["b", "a"]
TOML
cat >"$WORK/pkg/README.md" <<'MD'
# t7005
MD

export SHIRUDO_BUILD="$B" BPM_OCI_SCHEME=http
export REGISTRY_AUTH_FILE="$WORK/absent-auth.json" NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
unset BPM_OCI_CA_FILE BPM_OCI_USERNAME BPM_OCI_PASSWORD

test_expect_success 'bpm build packages the upatch with its tree metadata' '
	( cd "$WORK" && "$S" bpm build pkg --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	test -s "$WORK/t7005-1.0.0.bee"
'
[ -s "$WORK/t7005-1.0.0.bee" ] || test_done

# TOML spells the selector these ways too; read as unknown metadata or an
# unknown table, each left the operation without one, for every node.
for n in 1 2 3 4; do
	mkdir -p "$WORK/spelled/$n" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/spelled/$n/" &&
	printf '[package]\nname = "t7005"\n\n[[upatches]]\nsource = "t7005.bpf.c"\n\n' \
		>"$WORK/spelled/$n/Beefile"
done
printf '[upatches.tree]\nid = "t7005"\nselector.architecture = ["aarch64"]\n' \
	>>"$WORK/spelled/1/Beefile"
printf '[upatches.tree]\nid = "t7005"\nselector = { architecture = ["aarch64"] }\n' \
	>>"$WORK/spelled/2/Beefile"
printf '[upatches.tree]\nid = "t7005"\n\n[upatches .tree.selector]\narchitecture = ["aarch64"]\n' \
	>>"$WORK/spelled/3/Beefile"
printf '[upatches.tree]\nid = "t7005"\n\n["upatches".tree.selector]\narchitecture = ["aarch64"]\n' \
	>>"$WORK/spelled/4/Beefile"

# Targets the archive reader refuses or reads as another member.
n=5
for target in ./Beefile a/./data.txt dir/; do
	mkdir -p "$WORK/spelled/$n" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/spelled/$n/" &&
	echo data >"$WORK/spelled/$n/data.txt" &&
	printf '[package]\nname = "t7005"\n\n[[files]]\nsource = "data.txt"\ntarget = "%s"\n\n[[upatches]]\nsource = "t7005.bpf.c"\n' \
		"$target" >"$WORK/spelled/$n/Beefile"
	n=$((n + 1))
done

# A name that would be a file and a directory at once, in either order,
# below a member bpm build writes itself, and above the load artifact.
n=1
for pair in "a a/b" "a/b a" "data.txt README.md/data.txt" "data.txt upatches"; do
	mkdir -p "$WORK/nested/$n" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/nested/$n/" &&
	echo data >"$WORK/nested/$n/data.txt" &&
	printf '[package]\nname = "t7005"\n' >"$WORK/nested/$n/Beefile" &&
	for target in $pair; do
		printf '\n[[files]]\nsource = "data.txt"\ntarget = "%s"\n' \
			"$target" >>"$WORK/nested/$n/Beefile"
	done &&
	printf '\n[[upatches]]\nsource = "t7005.bpf.c"\n' >>"$WORK/nested/$n/Beefile"
	n=$((n + 1))
done

# Two members that each fit and together pass what a target unpacks, and
# one that passes it alone.
mkdir -p "$WORK/large" "$WORK/larger" &&
	ln -s "$REPO/vendor" "$WORK/large/vendor" &&
	ln -s "$REPO/bpf" "$WORK/large/bpf" &&
	ln -s "$REPO/vendor" "$WORK/larger/vendor" &&
	ln -s "$REPO/bpf" "$WORK/larger/bpf" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/large/" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/larger/" &&
	truncate -s 134217729 "$WORK/large/one" "$WORK/large/two" &&
	truncate -s 268435457 "$WORK/larger/one" &&
	printf '[package]\nname = "t7005"\n\n[[files]]\nsource = "one"\n\n[[files]]\nsource = "two"\n\n[[upatches]]\nsource = "t7005.bpf.c"\n' \
		>"$WORK/large/Beefile" &&
	printf '[package]\nname = "t7005"\n\n[[files]]\nsource = "one"\n\n[[upatches]]\nsource = "t7005.bpf.c"\n' \
		>"$WORK/larger/Beefile"

test_expect_success 'bpm build takes a SemVer version alone' '
	for v in 1.0 01.0.0 1.0.0.1 1.0.0_rc; do
		( cd "$WORK" && ! "$S" bpm build pkg --version $v \
			--keys-dir "$WORK/keys" ) 2>"$WORK/version.err" &&
		grep -q "is not a SemVer 2.0.0 version" "$WORK/version.err" &&
		! test -e "$WORK/t7005-$v.bee" || return 1
	done
'

test_expect_success 'bpm build refuses a tree selector or a target spelled another way' '
	for n in 1 2 3 4 5 6 7; do
		( cd "$WORK" && ! "$S" bpm build spelled/$n --version 9.0.$n \
			--keys-dir "$WORK/keys" ) 2>"$WORK/spelled/$n.err" &&
		grep -q "is not a valid Beefile" "$WORK/spelled/$n.err" &&
		! test -e "$WORK/t7005-9.0.$n.bee" || return 1
	done
'

test_expect_success 'bpm build refuses a target below another member' '
	for n in 1 2 3 4; do
		( cd "$WORK" && ! "$S" bpm build nested/$n --version 9.1.$n \
			--keys-dir "$WORK/keys" ) 2>"$WORK/nested/$n.err" &&
		grep -q "is not a valid Beefile" "$WORK/nested/$n.err" &&
		! test -e "$WORK/t7005-9.1.$n.bee" || return 1
	done
'

test_expect_success 'bpm build refuses members a target could not unpack together' '
	for n in large larger; do
		( cd "$WORK" && ! "$S" bpm build $n --version 9.2.0 \
			--keys-dir "$WORK/keys" ) 2>"$WORK/$n.err" &&
		grep -q "more than 256 MiB together, the most a target installs" \
			"$WORK/$n.err" &&
		! test -e "$WORK/t7005-9.2.0.bee" || return 1
	done
'

# $1 is the package directory under $WORK, $2 the value of the key.
fixes_package() {
	mkdir -p "$WORK/$1" &&
	cp "$WORK/pkg/t7005.bpf.c" "$WORK/$1/" &&
	ln -s "$REPO/vendor" "$WORK/$1/vendor" &&
	ln -s "$REPO/bpf" "$WORK/$1/bpf" &&
	printf '[package]\nname = "t7005"\n\n[[upatches]]\nsource = "t7005.bpf.c"\n\n[upatches.tree]\nid = "t7005"\nfixes = %s\n' \
		"$2" >"$WORK/$1/Beefile"
}
# $1 is the case, $2 the value, $3 what the refusal says.
fixes_refused() {
	fixes_package "fixes/$1" "$2" &&
	( cd "$WORK" && ! "$S" bpm build "fixes/$1" --version 8.0.0 \
		--keys-dir "$WORK/keys" ) 2>"$WORK/fixes/$1.err" &&
	grep -q "Beefile: $3" "$WORK/fixes/$1.err" &&
	grep -q "is not a valid Beefile" "$WORK/fixes/$1.err" &&
	! test -e "$WORK/t7005-8.0.0.bee"
}
# An array of $1 IDs, and one ID of $1 bytes.
fixes_ids() {
	python3 -c 'import sys; print("[" + ", ".join("\"ID-%d\"" % i for i in range(int(sys.argv[1]))) + "]")' "$1"
}
fixes_long() {
	python3 -c 'import sys; print("[\"" + "A" * int(sys.argv[1]) + "\"]")' "$1"
}

test_expect_success 'bpm build takes fixes of 1 to 16 IDs of 1 to 255 bytes' '
	fixes_package fixes/ok "[\"EXAMPLE-0101\", \"a.B_c:9-\"]" &&
	( cd "$WORK" && "$S" bpm build fixes/ok --version 8.1.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	tar -xzOf "$WORK/t7005-8.1.0.bee" t7005-8.1.0/Beefile |
		cmp - "$WORK/fixes/ok/Beefile" &&
	fixes_package fixes/max "$(fixes_ids 16)" &&
	( cd "$WORK" && "$S" bpm build fixes/max --version 8.2.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	fixes_package fixes/long "$(fixes_long 255)" &&
	( cd "$WORK" && "$S" bpm build fixes/long --version 8.3.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	test -s "$WORK/t7005-8.2.0.bee" && test -s "$WORK/t7005-8.3.0.bee"
'

test_expect_success 'bpm build refuses a malformed fixes' '
	fixes_refused many "$(fixes_ids 17)" "fixes holds more than 16 IDs" &&
	fixes_refused dup "[\"B\", \"A\", \"B\"]" "fixes holds B twice" &&
	fixes_refused empty-id "[\"A\", \"\"]" "fixes holds an empty ID" &&
	fixes_refused char "[\"A\", \"CVE 1\"]" "ID 2 of fixes has a character outside" &&
	fixes_refused slash "[\"a/b\"]" "ID 1 of fixes has a character outside" &&
	fixes_refused escape "[\"A\\n\"]" "ID 1 of fixes has a character outside" &&
	fixes_refused empty "[]" "fixes is not an array of 1 to 16 strings" &&
	fixes_refused string "\"EXAMPLE-0101\"" "fixes is not an array of 1 to 16 strings" &&
	fixes_refused number "[1]" "fixes is not an array of 1 to 16 strings" &&
	fixes_refused bare "7" "fixes is not an array of 1 to 16 strings" &&
	fixes_refused toolong "$(fixes_long 256)" "fixes is not an array of 1 to 16 strings" &&
	fixes_refused twice "[\"A\"]
fixes = [\"B\"]" "fixes is given twice"
'

PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
REG="$WORK/registry"
python3 ./helper/test-oci-registry.py --root "$REG" --port "$PORT" --writable \
	--log "$WORK/requests.log" --ready-file "$WORK/ready" &
SERVER_PID=$!
i=0
while [ ! -e "$WORK/ready" ]; do
	i=$((i + 1))
	[ "$i" -lt 100 ] || test_skip_all "registry fixture did not start"
	sleep .05
done
REGISTRY="127.0.0.1:$PORT"

# Verify a detached CMS blob against the operator certificate.
cms_verify() {
	openssl cms -verify -binary -inform DER -in "$1" -content "$2" \
		-certfile "${3:-$WORK/cert.pem}" -CAfile "${3:-$WORK/cert.pem}" -purpose any \
		-out /dev/null 2>/dev/null
}

# Split the two layers of an index or tree manifest into payload and
# signature files: $1 manifest path, $2 repository dir, $3 output prefix.
split_layers() {
	python3 - "$1" "$2" "$3" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
repo, out = pathlib.Path(sys.argv[2]), sys.argv[3]
assert manifest["schemaVersion"] == 2
for layer in manifest["layers"]:
    blob = (repo / "blobs" / layer["digest"]).read_bytes()
    assert len(blob) == layer["size"], layer
    kind = "sig" if layer["mediaType"].endswith(".signature.v1") or \
        layer["mediaType"].endswith(".signature.v1") else "payload"
    pathlib.Path(f"{out}.{kind}").write_bytes(blob)
pathlib.Path(f"{out}.artifact_type").write_text(manifest["artifactType"])
PY
}

# A registry that answers 404 for the index cannot be told from a namespace
# that never had one, and the operator would sign an index without every
# package it held: starting one takes --new-index.
test_expect_success 'bpm push refuses a namespace without an index unless told to start one' '
	! "$S" bpm push "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--keys-dir "$WORK/keys" >/dev/null 2>"$WORK/noindex.err" &&
	grep -q "has no repository index; pass --new-index" "$WORK/noindex.err" &&
	! test -e "$REG/ns/bpm-index/manifests/stable" &&
	! "$S" bpm push "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--new-index >/dev/null 2>"$WORK/noindex2.err" &&
	grep -q "new-index needs --keys-dir" "$WORK/noindex2.err"
'

test_expect_success 'bpm push publishes the package and a signed repository index' '
	"$S" bpm push "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--keys-dir "$WORK/keys" --new-index >"$WORK/push.out" 2>"$WORK/push.err" &&
	grep -qx "oci://$REGISTRY/ns/t7005:1.0.0 sha256:$(sha256sum \
		<"$REG/ns/t7005/manifests/1.0.0" | cut -d" " -f1)" "$WORK/push.out" &&
	test -s "$REG/ns/t7005/manifests/1.0.0" &&
	test -s "$REG/ns/bpm-index/manifests/stable" &&
	split_layers "$REG/ns/bpm-index/manifests/stable" "$REG/ns/bpm-index" "$WORK/index1" &&
	grep -qx "application/vnd.shirudo.bpm.index.v1" "$WORK/index1.artifact_type" &&
	cms_verify "$WORK/index1.sig" "$WORK/index1.payload"
'

test_expect_success 'the index entry describes the pushed manifest, package blob and signer' '
	python3 - "$WORK/index1.payload" "$REG" "$WORK/keys/cert.der" <<'"'"'PY'"'"'
import hashlib, json, pathlib, subprocess, sys
index = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
reg = pathlib.Path(sys.argv[2])
assert index["schema"] == 1, index
assert index["generated_at"].endswith("Z"), index
assert len(index["packages"]) == 1, index
e = index["packages"][0]
manifest = (reg / "ns/t7005/manifests/1.0.0").read_bytes()
assert e["name"] == "t7005" and e["version"] == "1.0.0", e
assert e["repository"] == "ns/t7005", e
assert e["manifest_digest"] == "sha256:" + hashlib.sha256(manifest).hexdigest(), e
layer = [l for l in json.loads(manifest)["layers"]
         if l["mediaType"] == "application/vnd.shirudo.bpm.package.v1+gzip"][0]
assert e["package_digest"] == layer["digest"] and e["package_size"] == layer["size"], e
pub = subprocess.run(["openssl", "x509", "-inform", "DER", "-in", sys.argv[3],
                      "-noout", "-pubkey"], check=True, capture_output=True).stdout
der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub,
                     check=True, capture_output=True).stdout
assert e["signer_fingerprint"] == hashlib.sha256(der).hexdigest(), e
PY
'

test_expect_success 'pushing the same package again keeps a single index entry' '
	"$S" bpm push "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--keys-dir "$WORK/keys" >/dev/null 2>&1 &&
	split_layers "$REG/ns/bpm-index/manifests/stable" "$REG/ns/bpm-index" "$WORK/index2" &&
	cms_verify "$WORK/index2.sig" "$WORK/index2.payload" &&
	python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
assert [(p[\"name\"], p[\"version\"]) for p in d[\"packages\"]] == [(\"t7005\", \"1.0.0\")], d
" "$WORK/index2.payload"
'

test_expect_success 'a second version is added to the index in sorted order' '
	( cd "$WORK" && "$S" bpm build pkg --version 0.9.0 --keys-dir "$WORK/keys" ) >/dev/null 2>&1 &&
	"$S" bpm push "$WORK/t7005-0.9.0.bee" "oci://$REGISTRY/ns/t7005" \
		--index-cert "$WORK/keys/cert.der" --index-key "$WORK/keys/signing_key.pem" \
		>/dev/null 2>&1 &&
	split_layers "$REG/ns/bpm-index/manifests/stable" "$REG/ns/bpm-index" "$WORK/index3" &&
	cms_verify "$WORK/index3.sig" "$WORK/index3.payload" &&
	python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
assert [(p[\"name\"], p[\"version\"]) for p in d[\"packages\"]] == [(\"t7005\", \"0.9.0\"), (\"t7005\", \"1.0.0\")], d
" "$WORK/index3.payload"
'

test_expect_success 'push without signing material leaves the index untouched' '
	( cd "$WORK" && "$S" bpm build pkg --version 2.0.0 --keys-dir "$WORK/keys" ) >/dev/null 2>&1 &&
	"$S" bpm push "$WORK/t7005-2.0.0.bee" "oci://$REGISTRY/ns/t7005" >/dev/null 2>&1 &&
	test -s "$REG/ns/t7005/manifests/2.0.0" &&
	split_layers "$REG/ns/bpm-index/manifests/stable" "$REG/ns/bpm-index" "$WORK/index4" &&
	cmp -s "$WORK/index3.payload" "$WORK/index4.payload"
'

test_expect_success 'push refuses to start an index where one exists' '
	! "$S" bpm push "$WORK/t7005-2.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--keys-dir "$WORK/keys" --new-index >/dev/null 2>"$WORK/newindex.err" &&
	grep -q "has a repository index already" "$WORK/newindex.err" &&
	split_layers "$REG/ns/bpm-index/manifests/stable" "$REG/ns/bpm-index" "$WORK/index5" &&
	cmp -s "$WORK/index3.payload" "$WORK/index5.payload"
'

test_expect_success 'push refuses half of the index signing pair' '
	! "$S" bpm push "$WORK/t7005-2.0.0.bee" "oci://$REGISTRY/ns/t7005" \
		--index-cert "$WORK/keys/cert.der" >/dev/null 2>&1
'

test_expect_success 'bpm tree append creates a signed first-generation publication' '
	"$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--keys-dir "$WORK/keys" >"$WORK/append1.out" 2>"$WORK/append1.err" &&
	grep -q "^oci://$REGISTRY/ns/tree:stable sha256:" "$WORK/append1.out" &&
	cp "$REG/ns/tree/manifests/stable" "$WORK/tree1.manifest" &&
	split_layers "$WORK/tree1.manifest" "$REG/ns/tree" "$WORK/tree1" &&
	grep -qx "application/vnd.shirudo.upatch.tree.v1" "$WORK/tree1.artifact_type" &&
	cms_verify "$WORK/tree1.sig" "$WORK/tree1.payload"
'

# The operations must describe the artifacts inside the published 1.0.0
# archive, not the later rebuilds in the package directory.
mkdir -p "$WORK/art" && tar -xzf "$WORK/t7005-1.0.0.bee" -C "$WORK/art" 2>/dev/null || :
"$S" upatch info --json "$WORK/art/t7005-1.0.0/upatches/t7005.upatch" >"$WORK/load.json" 2>/dev/null || :
"$S" upatch info --json "$WORK/art/t7005-1.0.0/upatches/t7005.unload.upatch" >"$WORK/unload.json" 2>/dev/null || :

test_expect_success 'the publication carries one canonical add operation' '
	python3 - "$WORK/tree1.payload" "$REG/ns/tree" "$REGISTRY" "$WORK/load.json" <<'"'"'PY'"'"'
import hashlib, json, pathlib, sys
pub = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
repo, registry = pathlib.Path(sys.argv[2]), sys.argv[3]
load = json.load(open(sys.argv[4]))
assert pub["schema"] == 1 and pub["tree_id"] == "t7005", pub
assert pub["generation"] == 1 and "parent_manifest_digest" not in pub, pub
assert pub["base"] == {"seq": 0} and pub["head"] == {"seq": 1}, pub
assert len(pub["operations"]) == 1, pub
op = pub["operations"][0]
assert op["seq"] == 1 and op["op"] == "add" and op["id"] == "t7005", op
assert op["selector"] == {"architecture": ["aarch64", "x86_64"],
                          "kernel_release_prefix": ["7."],
                          "labels": {"env": ["a", "b"]}}, op["selector"]
art = op["artifact"]
assert art["repository"] == f"oci://{registry}/ns/tree", art
assert art["payload_sha256"] == "sha256:" + load["payload_sha256"], art
assert load["type"] == "load", load
short = load["payload_sha256"][:16]
manifest = (repo / "manifests" / f"upatch-t7005-{short}").read_bytes()
assert art["manifest_digest"] == "sha256:" + hashlib.sha256(manifest).hexdigest(), art
layer = json.loads(manifest)["layers"][0]
assert layer["mediaType"] == "application/vnd.shirudo.upatch.v1", layer
assert art["layer_digest"] == layer["digest"], art
blob = (repo / "blobs" / layer["digest"]).read_bytes()
assert hashlib.sha256(blob).hexdigest() == layer["digest"][7:], layer
canonical = json.dumps({"seq": op["seq"], "op": op["op"], "id": op["id"],
                        "selector": op["selector"], "artifact": art},
                       separators=(",", ":")).encode()
assert op["operation_digest"] == "sha256:" + hashlib.sha256(canonical).hexdigest(), op
PY
'

test_expect_success 'a delete append chains on the previous publication' '
	"$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/keys" --op delete >/dev/null 2>&1 &&
	split_layers "$REG/ns/tree/manifests/stable" "$REG/ns/tree" "$WORK/tree2" &&
	cms_verify "$WORK/tree2.sig" "$WORK/tree2.payload" &&
	python3 - "$WORK/tree2.payload" "$WORK/tree1.manifest" "$WORK/tree1.payload" "$WORK/unload.json" <<'"'"'PY'"'"'
import hashlib, json, pathlib, sys
pub = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
parent = pathlib.Path(sys.argv[2]).read_bytes()
first = json.loads(pathlib.Path(sys.argv[3]).read_bytes())
unload = json.load(open(sys.argv[4]))
assert pub["generation"] == 2 and pub["head"] == {"seq": 2}, pub
assert pub["parent_manifest_digest"] == "sha256:" + hashlib.sha256(parent).hexdigest(), pub
assert pub["operations"][0] == first["operations"][0], pub
op = pub["operations"][1]
assert op["seq"] == 2 and op["op"] == "delete" and op["id"] == "t7005", op
assert unload["type"] == "unload", unload
assert op["artifact"]["payload_sha256"] == "sha256:" + unload["payload_sha256"], op
PY
'

test_expect_success 'tree append refuses another tree id, none, and a package without tree entries' '
	! "$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--keys-dir "$WORK/keys" --tree-id other >/dev/null 2>"$WORK/other.err" &&
	grep -q "holds tree t7005, not other; refusing to extend another tree" \
		"$WORK/other.err" &&
	! "$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--keys-dir "$WORK/keys" >/dev/null 2>"$WORK/noid.err" &&
	grep -q "holds tree t7005; name the tree to extend with --tree-id" \
		"$WORK/noid.err" &&
	python3 - "$WORK" <<'"'"'PY'"'"'
import io, pathlib, sys, tarfile
work = pathlib.Path(sys.argv[1])
body = io.BytesIO()
with tarfile.open(fileobj=body, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
    for name, content in (("plain-1.0/Beefile", b"[package]\nname = \"plain\"\n"),
                          ("plain-1.0/build-environment.json",
                           b"{\"package\":{\"name\":\"plain\",\"version\":\"1.0\"}}"),
                          ("plain-1.0/cert.der", (work / "keys/cert.der").read_bytes())):
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
(work / "plain.bee").write_bytes(body.getvalue())
PY
	! "$S" bpm tree append "$WORK/plain.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/keys" >/dev/null 2>"$WORK/plain.err" &&
	grep -q "no \[upatches.tree\] entries" "$WORK/plain.err"
'

# A package of one XDP upatch named $1 for the device classes $2, with $3
# as the rest of its tree entry. A second name $4 adds an upatch for the
# same classes.
xdp_package() {
	mkdir -p "$WORK/$1" &&
	ln -s "$REPO/vendor" "$WORK/$1/vendor" &&
	ln -s "$REPO/bpf" "$WORK/$1/bpf" &&
	printf '[package]\nname = "%s"\n' "$1" >"$WORK/$1/Beefile" &&
	for name in $1 ${4:-}; do
		printf '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause\n#include "vmlinux.h"\n#include <bpf/bpf_helpers.h>\n\nchar _license[] SEC("license") = "Dual BSD/GPL";\n\nSEC("xdp/%s")\nint xdp_pass(struct xdp_md *ctx)\n{\n\treturn XDP_PASS;\n}\n' \
			"$2" >"$WORK/$1/$name.bpf.c" &&
		printf '\n[[upatches]]\nsource = "%s.bpf.c"\n\n[upatches.tree]\nid = "%s"\n%b' \
			"$name" "$name" "$3" >>"$WORK/$1/Beefile" || return 1
	done &&
	( cd "$WORK" && "$S" bpm build "$1" --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2
}
site() {
	printf '\\n[upatches.tree.selector.labels]\\nsite = [%s]\\n' "$1"
}
xdp_append() {
	"$S" bpm tree append "$WORK/$1-1.0.0.bee" "oci://$REGISTRY/ns/xdp" \
		--keys-dir "$WORK/keys" --tree-id xdp "${2:---op=add}" \
		>/dev/null 2>"$WORK/$1.err"
}
xdp_refused() {
	if xdp_append "$1"; then
		return 1
	fi
	grep -q "$1 and $2 both select XDP device classes $3 " "$WORK/$1.err"
}

# A device runs one native XDP program, so the second of two upatches that
# select a class fails its load wherever such a device is, and tree sync
# stops there on every node the two reach.
test_expect_success 'tree append refuses an XDP device class another upatch of the tree selects' '
	xdp_package t7005xa 3 "$(site \"a\")" &&
	xdp_package t7005xb 2 "$(site "\"a\", \"b\"")" &&
	xdp_append t7005xa &&
	cp "$REG/ns/xdp/manifests/stable" "$WORK/xdp1.manifest" &&
	xdp_refused t7005xb "t7005xa (seq 1)" 2 &&
	cmp -s "$WORK/xdp1.manifest" "$REG/ns/xdp/manifests/stable" &&
	! ls "$REG/ns/xdp/manifests" | grep -q "upatch-t7005xb"
'

test_expect_success 'tree append takes the class once the upatch that held it is deleted' '
	xdp_append t7005xa --op=delete &&
	xdp_append t7005xb &&
	xdp_package t7005xc 1 "$(site \"a\")" &&
	xdp_append t7005xc
'

test_expect_success 'tree append takes a shared class on selectors that exclude each other, and another class' '
	xdp_package t7005xd 2 "$(site \"c\")" &&
	xdp_append t7005xd &&
	xdp_package t7005xe 8 "" &&
	xdp_append t7005xe &&
	xdp_package t7005xf 2 "" &&
	xdp_refused t7005xf "t7005xb (seq 3)" 2
'

# A Java upatch has no XDP program: its add selects no class, and an XDP
# add whose selector meets it reads it without refusing either.
test_expect_success 'tree append takes a Java upatch beside the XDP upatches' '
	mkdir -p "$WORK/t7005ja" &&
	python3 -I -c "
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], \"w\") as z:
    z.writestr(\"META-INF/MANIFEST.MF\", \"Manifest-Version: 1.0\\nPremain-Class: A\\n\")
" "$WORK/t7005ja/t7005ja.jar" &&
	printf "[package]\nname = \"t7005ja\"\n\n[[upatches]]\nsource = \"t7005ja.jar\"\ntype = \"java\"\n\n[upatches.tree]\nid = \"t7005ja\"\n" \
		>"$WORK/t7005ja/Beefile" &&
	( cd "$WORK" && "$S" bpm build t7005ja --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	xdp_append t7005ja &&
	ls "$REG/ns/xdp/manifests" | grep -q "^upatch-t7005ja-" &&
	xdp_package t7005xj 1 "$(site \"z\")" &&
	xdp_append t7005xj &&
	xdp_append t7005ja --op=delete
'

test_expect_success 'tree append refuses two upatches of one package that select a class' '
	xdp_package t7005xg 16 "" t7005xh &&
	! "$S" bpm tree append "$WORK/t7005xg-1.0.0.bee" "oci://$REGISTRY/ns/xdp2" \
		--keys-dir "$WORK/keys" >/dev/null 2>"$WORK/t7005xg.err" &&
	grep -q "t7005xh and t7005xg (seq 1) both select XDP device classes 16 " \
		"$WORK/t7005xg.err" &&
	! test -e "$REG/ns/xdp2"
'

# No node can digest an operation with a control character in it, so the
# entry is refused, and before its artifact reaches the registry.
test_expect_success 'tree append uploads nothing for an entry no target would take' '
	xdp_package t7005ct 16 "$(site "\"a\\\\tb\"")" &&
	grep -q "^site = \[\"a.tb\"\]\$" "$WORK/t7005ct/Beefile" &&
	! "$S" bpm tree append "$WORK/t7005ct-1.0.0.bee" "oci://$REGISTRY/ns/ctl" \
		--keys-dir "$WORK/keys" >/dev/null 2>"$WORK/t7005ct.err" &&
	grep -q "the tree entry of t7005ct makes an operation no target takes" \
		"$WORK/t7005ct.err" &&
	! test -e "$REG/ns/ctl"
'

test_expect_success 'the operator commands are reachable directly in shirudo-build' '
	"$B" bpm --help 2>&1 | grep -q "tree append <package-file> <repository>" &&
	"$B" bpm tree append --help 2>&1 | grep -q "\-\-op add|delete" &&
	"$B" bpm push --help 2>&1 | grep -q "<namespace>/bpm-index:stable" &&
	! "$B" bpm not-a-command >/dev/null 2>&1
'

test_expect_success 'tree append needs readable signing material' '
	! "$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --key "$WORK/missing.pem" \
		--cert "$WORK/keys/cert.der" >/dev/null 2>&1
'

test_expect_success 'a new signing key does not silently replace the previous tree signer' '
	"$S" genkey --keys-dir "$WORK/next-key" >/dev/null &&
	openssl x509 -inform DER -in "$WORK/next-key/cert.der" -out "$WORK/next-key.pem" &&
	cp "$REG/ns/tree/manifests/stable" "$WORK/before-rotation.manifest" &&
	! "$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/next-key" >/dev/null 2>&1 &&
	cmp "$REG/ns/tree/manifests/stable" "$WORK/before-rotation.manifest"
'

test_expect_success 'previous-cert verifies A while B signs the next publication' '
	"$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/next-key" --previous-cert "$WORK/keys/cert.der" >/dev/null &&
	split_layers "$REG/ns/tree/manifests/stable" "$REG/ns/tree" "$WORK/rotated" &&
	cms_verify "$WORK/rotated.sig" "$WORK/rotated.payload" "$WORK/next-key.pem" &&
	! cms_verify "$WORK/rotated.sig" "$WORK/rotated.payload" &&
	python3 - "$WORK/rotated.payload" "$WORK/before-rotation.manifest" <<"PYTEST"
import hashlib, json, pathlib, sys
publication = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
parent = pathlib.Path(sys.argv[2]).read_bytes()
assert publication["parent_manifest_digest"] == "sha256:" + hashlib.sha256(parent).hexdigest()
assert publication["generation"] == 3 and publication["head"] == {"seq": 3}
PYTEST
'

test_expect_success 'later B publications use B to verify the predecessor by default' '
	"$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/next-key" >/dev/null &&
	split_layers "$REG/ns/tree/manifests/stable" "$REG/ns/tree" "$WORK/after-rotation" &&
	cms_verify "$WORK/after-rotation.sig" "$WORK/after-rotation.payload" "$WORK/next-key.pem" &&
	python3 -c "import json, sys; p=json.load(open(sys.argv[1])); assert p[\"generation\"] == 4" \
		"$WORK/after-rotation.payload"
'

test_expect_success 'a wrong explicit predecessor certificate leaves the tree unchanged' '
	cp "$REG/ns/tree/manifests/stable" "$WORK/rotated.manifest" &&
	! "$S" bpm tree append "$WORK/t7005-1.0.0.bee" "oci://$REGISTRY/ns/tree" \
		--tree-id t7005 --keys-dir "$WORK/next-key" --previous-cert="$WORK/keys/cert.der" >/dev/null 2>&1 &&
	cmp "$REG/ns/tree/manifests/stable" "$WORK/rotated.manifest"
'

test_done
