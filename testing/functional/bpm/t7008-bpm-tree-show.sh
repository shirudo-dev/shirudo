#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7008 -- bpm tree show prints a tree publication's manifest digest and
# its document bytes verbatim, fixes included, after verifying it as tree
# sync does; refuses a bad signature, a wrong certificate, a tampered
# layer and a signed document sync would refuse with the errno sync
# reports; and writes nothing to the registry. With --walk it prints every
# segment of a sealed tree, oldest first, and refuses a lost segment.
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

"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 &&
	"$S" genkey --keys-dir "$WORK/other" >/dev/null 2>&1 ||
	test_skip_all "genkey failed"
CERT="$WORK/keys/cert.der"

export SHIRUDO_BUILD="$B" BPM_OCI_SCHEME=http
export REGISTRY_AUTH_FILE="$WORK/absent-auth.json" NO_PROXY=127.0.0.1 no_proxy=127.0.0.1
unset BPM_OCI_CA_FILE BPM_OCI_USERNAME BPM_OCI_PASSWORD

mkdir -p "$WORK/t7008" &&
ln -s "$REPO/vendor" "$WORK/t7008/vendor" &&
ln -s "$REPO/bpf" "$WORK/t7008/bpf" &&
printf '// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause\n#include "vmlinux.h"\n#include <bpf/bpf_helpers.h>\n#include <bpf/bpf_tracing.h>\n\nchar _license[] SEC("license") = "Dual BSD/GPL";\n\nSEC("fentry/do_nanosleep")\nint BPF_PROG(t7008_fn)\n{\n\treturn 0;\n}\n' \
	>"$WORK/t7008/t7008.bpf.c" &&
printf '[package]\nname = "t7008"\n\n[[upatches]]\nsource = "t7008.bpf.c"\n\n[upatches.tree]\nid = "t7008"\nfixes = ["EXAMPLE-0101"]\n' \
	>"$WORK/t7008/Beefile" ||
	test_skip_all "cannot write the package sources"

test_expect_success 'bpm build packages an upatch with fixes' '
	( cd "$WORK" && "$S" bpm build t7008 --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >&2 &&
	test -s "$WORK/t7008-1.0.0.bee"
'
[ -s "$WORK/t7008-1.0.0.bee" ] || test_done

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
TREE="oci://127.0.0.1:$PORT/ns/tree"

# A digest of every file of the registry, to show that show writes none.
registry_sum() {
	(cd "$REG" && find . -type f | LC_ALL=C sort | xargs sha256sum)
}

# Run show with $@; its output lands in $WORK/out, its errors in
# $WORK/err.
show() {
	"$S" bpm tree show "$@" >"$WORK/out" 2>"$WORK/err"
}

# show refuses with exit status 1 and "bpm tree show: $1", prints
# nothing on standard output, and leaves the registry as it was.
refused() {
	msg=$1
	shift
	registry_sum >"$WORK/before" &&
	{ show "$@"; test $? -eq 1; } &&
	grep -qxF "bpm tree show: $msg" "$WORK/err" &&
	test ! -s "$WORK/out" &&
	registry_sum >"$WORK/after" &&
	cmp -s "$WORK/before" "$WORK/after"
}

test_expect_success 'tree append publishes the package with its fixes' '
	"$S" bpm tree append "$WORK/t7008-1.0.0.bee" "$TREE" \
		--keys-dir "$WORK/keys" >"$WORK/append.out" &&
	"$S" bpm tree append "$WORK/t7008-1.0.0.bee" "$TREE" \
		--keys-dir "$WORK/keys" --reference beta >>"$WORK/append.out" &&
	test "$(wc -l <"$WORK/append.out")" -eq 2
'

test_expect_success 'show prints the digest and the document bytes verbatim' '
	registry_sum >"$WORK/before" &&
	show "$TREE" --cert "$CERT" &&
	registry_sum >"$WORK/after" &&
	cmp -s "$WORK/before" "$WORK/after" &&
	test ! -s "$WORK/err" &&
	python3 - "$REG/ns/tree" "$WORK/out" "$(head -n1 "$WORK/append.out")" <<-\PY
	import hashlib, json, pathlib, sys
	repo, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
	raw = (repo / "manifests" / "stable").read_bytes()
	digest = "sha256:" + hashlib.sha256(raw).hexdigest()
	assert sys.argv[3].endswith(" " + digest), sys.argv[3]
	manifest = json.loads(raw)
	layer = [l for l in manifest["layers"] if l["mediaType"].endswith("+json")][0]
	document = (repo / "blobs" / layer["digest"]).read_bytes()
	text = out.read_bytes()
	assert text == (b"{\"manifest_digest\":\"" + digest.encode() +
	                b"\",\"document\":" + document + b"}\n"), text
	shown = json.loads(text)
	assert list(shown) == ["manifest_digest", "document"], shown
	op = shown["document"]["operations"][0]
	assert op["fixes"] == ["EXAMPLE-0101"], op
	PY
'

test_expect_success 'show takes --reference and its value after =' '
	show "$TREE" --cert="$CERT" --reference=beta &&
	python3 -c "
import json, sys
shown = json.load(open(sys.argv[1]))
assert sys.argv[2].endswith(\" \" + shown[\"manifest_digest\"]), shown
" "$WORK/out" "$(tail -n1 "$WORK/append.out")"
'

test_expect_success 'show refuses a reference that does not exist' '
	refused "No such file or directory" "$TREE" --cert "$CERT" \
		--reference absent
'

test_expect_success 'append refuses the tree of another reference served in place' '
	cp "$REG/ns/tree/manifests/stable" "$WORK/stable" &&
	cp "$REG/ns/tree/manifests/beta" "$REG/ns/tree/manifests/stable" &&
	registry_sum >"$WORK/before" &&
	! "$S" bpm tree append "$WORK/t7008-1.0.0.bee" "$TREE" \
		--tree-id t7008 --keys-dir "$WORK/keys" >"$WORK/out" 2>"$WORK/err" &&
	grep -q "holds tree t7008-beta, not t7008;" "$WORK/err" &&
	registry_sum >"$WORK/after" &&
	cmp -s "$WORK/before" "$WORK/after" &&
	cp "$WORK/stable" "$REG/ns/tree/manifests/stable"
'

test_expect_success 'show refuses a wrong certificate' '
	refused "Key was rejected by service" "$TREE" \
		--cert "$WORK/other/cert.der"
'

# Replace the stable publication's layer of media type $1 with $2, a
# file, under the digest of the bytes or, with $3 set, under the old one.
replace_layer() {
	python3 - "$REG/ns/tree" "$1" "$2" "${3:-}" <<-\PY
	import hashlib, json, pathlib, sys
	repo, media = pathlib.Path(sys.argv[1]), sys.argv[2]
	body = pathlib.Path(sys.argv[3]).read_bytes()
	path = repo / "manifests" / "stable"
	manifest = json.loads(path.read_bytes())
	layer = [l for l in manifest["layers"] if l["mediaType"] == media][0]
	if sys.argv[4]:
	    (repo / "blobs" / layer["digest"]).write_bytes(body)
	else:
	    layer["digest"] = "sha256:" + hashlib.sha256(body).hexdigest()
	    layer["size"] = len(body)
	    (repo / "blobs" / layer["digest"]).write_bytes(body)
	    path.write_bytes(json.dumps(manifest, separators=(",", ":")).encode())
	PY
}

# Sign $1, a document, with the keys in directory $2 into $1.sig.
sign() {
	openssl cms -sign -binary -md sha512 -in "$1" -signer "$2/cert.der" \
		-inkey "$2/signing_key.pem" -outform DER -out "$1.sig" \
		-nosmimecap -nocerts -keyid
}

# Put back the publication the appends left.
restore() {
	rm -rf "$REG/ns/tree" && cp -R "$WORK/saved" "$REG/ns/tree"
}

DOC_MEDIA=application/vnd.shirudo.upatch.tree.v1+json
SIG_MEDIA=application/vnd.shirudo.upatch.tree.signature.v1

test_expect_success 'show refuses a signature by another key' '
	cp -R "$REG/ns/tree" "$WORK/saved" &&
	python3 - "$REG/ns/tree" "$WORK/doc.json" <<-\PY &&
	import json, pathlib, sys
	repo = pathlib.Path(sys.argv[1])
	manifest = json.loads((repo / "manifests" / "stable").read_bytes())
	layer = [l for l in manifest["layers"] if l["mediaType"].endswith("+json")][0]
	pathlib.Path(sys.argv[2]).write_bytes((repo / "blobs" / layer["digest"]).read_bytes())
	PY
	sign "$WORK/doc.json" "$WORK/other" &&
	replace_layer "$SIG_MEDIA" "$WORK/doc.json.sig" &&
	refused "Key was rejected by service" "$TREE" --cert "$CERT"
'

test_expect_success 'show refuses a classical certificate and signature' '
	restore &&
	mkdir -p "$WORK/rsa" &&
	openssl req -x509 -newkey rsa:2048 -nodes \
		-keyout "$WORK/rsa/signing_key.pem" \
		-out "$WORK/rsa/cert.pem" -days 1 -sha256 \
		-subj "/CN=t7008-rsa" >/dev/null 2>&1 &&
	openssl x509 -in "$WORK/rsa/cert.pem" -outform DER \
		-out "$WORK/rsa/cert.der" &&
	openssl cms -sign -binary -md sha256 -in "$WORK/doc.json" \
		-signer "$WORK/rsa/cert.pem" \
		-inkey "$WORK/rsa/signing_key.pem" -outform DER \
		-out "$WORK/doc.json.sig" -nosmimecap -nocerts -keyid &&
	replace_layer "$SIG_MEDIA" "$WORK/doc.json.sig" &&
	refused "Key was rejected by service" "$TREE" \
		--cert "$WORK/rsa/cert.der"
'

test_expect_success 'show refuses a document its signature does not cover' '
	restore &&
	sed "s/EXAMPLE-0101/EXAMPLE-0102/" "$WORK/doc.json" >"$WORK/forged.json" &&
	replace_layer "$DOC_MEDIA" "$WORK/forged.json" &&
	refused "Key was rejected by service" "$TREE" --cert "$CERT"
'

test_expect_success 'show refuses a layer that does not match its digest' '
	restore &&
	replace_layer "$DOC_MEDIA" "$WORK/forged.json" keep &&
	refused "Key was rejected by service" "$TREE" --cert "$CERT"
'

# Publish $1, a document, signed with the operator key.
resigned() {
	sign "$1" "$WORK/keys" &&
	replace_layer "$DOC_MEDIA" "$1" &&
	replace_layer "$SIG_MEDIA" "$1.sig"
}

test_expect_success 'show prints a re-signed document with other fixes as signed' '
	restore &&
	resigned "$WORK/forged.json" &&
	show "$TREE" --cert "$CERT" &&
	python3 -c "
import json, sys
shown = json.load(open(sys.argv[1]))
assert shown[\"document\"][\"operations\"][0][\"fixes\"] == [\"EXAMPLE-0102\"], shown
" "$WORK/out"
'

test_expect_success 'show refuses a signed document tree sync would refuse' '
	restore &&
	sed "s/\"id\":\"t7008\"/\"id\":\"t7009\"/" "$WORK/doc.json" >"$WORK/renamed.json" &&
	! cmp -s "$WORK/doc.json" "$WORK/renamed.json" &&
	resigned "$WORK/renamed.json" &&
	refused "Key was rejected by service" "$TREE" --cert "$CERT" &&
	restore &&
	printf "not json" >"$WORK/text.json" &&
	resigned "$WORK/text.json" &&
	refused "Invalid argument" "$TREE" --cert "$CERT"
'

test_expect_success 'show without --cert is a usage error' '
	restore &&
	{ show "$TREE"; test $? -eq 2; } &&
	grep -qx "bpm tree show: takes <repository> and --cert <cert.der>" \
		"$WORK/err" &&
	test ! -s "$WORK/out" &&
	show "$TREE" --cert "$CERT"
'

test_expect_success 'show --walk of a tree never sealed prints what show prints' '
	show "$TREE" --cert "$CERT" &&
	mv "$WORK/out" "$WORK/plain" &&
	show "$TREE" --cert "$CERT" --walk &&
	cmp -s "$WORK/plain" "$WORK/out"
'

SEGS="oci://127.0.0.1:$PORT/ns/segs"

# The digest of the manifest in the file $1.
manifest_digest() {
	printf 'sha256:%s\n' "$(sha256sum <"$1" | cut -d" " -f1)"
}

test_expect_success 'tree append with --segment-ops 1 seals a segment per append' '
	n=0 &&
	for op in add delete add; do
		"$S" bpm tree append "$WORK/t7008-1.0.0.bee" "$SEGS" \
			--tree-id t7008 --keys-dir "$WORK/keys" --segment-ops 1 \
			--op "$op" >/dev/null || return 1
		n=$((n + 1)) &&
		cp "$REG/ns/segs/manifests/stable" "$WORK/g$n" || return 1
	done
'

test_expect_success 'show --walk prints every segment, oldest first, as show prints it' '
	registry_sum >"$WORK/before" &&
	show "$SEGS" --cert "$CERT" --walk &&
	registry_sum >"$WORK/after" &&
	cmp -s "$WORK/before" "$WORK/after" &&
	test ! -s "$WORK/err" &&
	python3 - "$REG/ns/segs" "$WORK/out" "$WORK/g1" "$WORK/g2" "$WORK/g3" <<-\PY
	import hashlib, json, pathlib, sys
	repo, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
	expected = b""
	for path in sys.argv[3:]:
	    raw = pathlib.Path(path).read_bytes()
	    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
	    manifest = json.loads(raw)
	    layer = [l for l in manifest["layers"] if l["mediaType"].endswith("+json")][0]
	    document = (repo / "blobs" / layer["digest"]).read_bytes()
	    expected += (b"{\"manifest_digest\":\"" + digest.encode() +
	                 b"\",\"document\":" + document + b"}\n")
	text = out.read_bytes()
	assert text == expected, text
	decoder, rest, bases = json.JSONDecoder(), text.decode(), []
	while rest.strip():
	    shown, end = decoder.raw_decode(rest.lstrip())
	    rest = rest.lstrip()[end:]
	    bases.append(shown["document"]["base"]["seq"])
	assert bases == [0, 1, 2], bases
	PY
'

test_expect_success 'show --walk from a sealed segment stops at seq 0' '
	g2=$(manifest_digest "$WORK/g2") &&
	show "$SEGS" --cert "$CERT" --walk --reference "$g2" &&
	test "$(grep -c "^{\"manifest_digest\"" "$WORK/out")" -eq 2 &&
	tail -n1 "$WORK/out" | grep -q "^{\"manifest_digest\":\"$g2\""
'

test_expect_success 'show --walk refuses a tree whose sealed segment is gone' '
	g1=$(manifest_digest "$WORK/g1") &&
	mv "$REG/ns/segs/manifests/$g1" "$WORK/sealed" &&
	{ refused "No such file or directory" "$SEGS" --cert "$CERT" --walk
	  ret=$?; } &&
	mv "$WORK/sealed" "$REG/ns/segs/manifests/$g1" &&
	test "$ret" -eq 0
'

test_done
