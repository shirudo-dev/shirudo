#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3014 -- Java agent upatches: shirudo build signs a .jar into a Java
# load and its unload directive, offline (no kernel, no root), and the
# reader refuses a header whose type the signed sections do not carry.
# The jar is a zip that python3 writes; no JDK is needed.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build

command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

openssl req -x509 -newkey ML-DSA-87 -nodes -keyout "$WORK/k.pem" \
	-outform DER -out "$WORK/c.der" -days 1 -subj "/CN=t3014" \
	>/dev/null 2>&1 || test_skip_all "openssl ML-DSA keygen failed (needs OpenSSL >= 3.5)"
chmod 600 "$WORK/k.pem"

python3 -I - "$WORK/agent.jar" <<'PY'
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("META-INF/MANIFEST.MF",
               "Manifest-Version: 1.0\nPremain-Class: t3014.Agent\n\n")
    z.writestr("t3014/Agent.class", b"\xca\xfe\xba\xbe")
PY

info() {
	"$S" upatch info "$1" --json 2>/dev/null
}

field() {
	python3 -I -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

test_expect_success 'a jar becomes a signed Java load' '
	"$SHB" "$WORK/agent.jar" --key "$WORK/k.pem" --cert "$WORK/c.der" \
		>/dev/null 2>&1 &&
	test -f "$WORK/agent.upatch" &&
	info "$WORK/agent.upatch" >"$WORK/load.json" &&
	python3 -I - "$WORK/load.json" "$WORK/agent.jar" <<-PY
	import json, sys
	d = json.load(open(sys.argv[1]))
	jar = open(sys.argv[2], "rb").read()
	assert d["type"] == "load", d
	assert d["payload_type"] == "java", d
	assert d["name"] == "agent" and d["signed_name"] == "agent", d
	assert d["loader_insns_len"] == 0, d
	assert d["signature_len"] > 0, d
	assert d["jar_len"] == len(jar), d
	assert d["attach_metadata_len"] == 0 and not d["decoders"], d
	PY
'

test_expect_success 'the payload digest is SHA-256 of the signed data' '
	python3 -I - "$WORK/agent.upatch" "$(field payload_sha256 <"$WORK/load.json")" <<-PY
	import hashlib, struct, sys
	b = open(sys.argv[1], "rb").read()
	off, length = struct.unpack_from("<II", b, 328)
	assert hashlib.sha256(b[off:off + length]).hexdigest() == sys.argv[2]
	PY
'

test_expect_success 'the signature covers the data alone' '
	python3 -I - "$WORK/agent.upatch" "$WORK" <<-PY &&
	import struct, sys
	b = open(sys.argv[1], "rb").read()
	sig_off, sig_len = struct.unpack_from("<II", b, 312)
	data_off, data_len = struct.unpack_from("<II", b, 328)
	open(sys.argv[2] + "/sig.der", "wb").write(b[sig_off:sig_off + sig_len])
	open(sys.argv[2] + "/data.bin", "wb").write(b[data_off:data_off + data_len])
	PY
	openssl x509 -inform DER -in "$WORK/c.der" -out "$WORK/c.pem" &&
	openssl cms -verify -binary -inform DER -in "$WORK/sig.der" \
		-content "$WORK/data.bin" -certfile "$WORK/c.pem" -nointern \
		-noverify -out /dev/null 2>/dev/null
'

test_expect_success 'the unload directive of a Java upatch' '
	payload=$(field payload_sha256 <"$WORK/load.json") &&
	"$SHB" --unload agent --java --payload-sha256 "$payload" \
		--key "$WORK/k.pem" --cert "$WORK/c.der" \
		-o "$WORK/agent.unload.upatch" >/dev/null 2>&1 &&
	info "$WORK/agent.unload.upatch" >"$WORK/unload.json" &&
	python3 -I - "$WORK/unload.json" "$payload" <<-PY
	import json, sys
	d = json.load(open(sys.argv[1]))
	assert d["type"] == "unload" and d["payload_type"] == "java", d
	assert d["unload_payload_sha256"] == sys.argv[2], d
	assert d["jar_len"] == 0, d
	PY
'

test_expect_success '--java takes --unload and --payload-sha256' '
	{ "$SHB" "$WORK/agent.jar" --java --key "$WORK/k.pem" \
		--cert "$WORK/c.der" 2>/dev/null; test $? -eq 2; } &&
	{ "$SHB" --unload agent --java --key "$WORK/k.pem" \
		--cert "$WORK/c.der" 2>/dev/null; test $? -eq 2; }
'

test_expect_success 'a file that is no jar is refused' '
	printf "not a zip" >"$WORK/bad.jar" &&
	! "$SHB" "$WORK/bad.jar" --key "$WORK/k.pem" --cert "$WORK/c.der" \
		-o "$WORK/bad.upatch" 2>/dev/null &&
	test ! -e "$WORK/bad.upatch"
'

test_expect_success 'a jar without a Premain-Class is refused' '
	python3 -I -c "
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], \"w\", zipfile.ZIP_DEFLATED) as z:
    z.writestr(\"META-INF/MANIFEST.MF\", \"Manifest-Version: 1.0\\nMain-Class: A\\n\")
" "$WORK/lib.jar" &&
	! "$SHB" "$WORK/lib.jar" --key "$WORK/k.pem" --cert "$WORK/c.der" \
		-o "$WORK/lib.upatch" 2>"$WORK/lib.err" &&
	grep -q "no Premain-Class" "$WORK/lib.err" &&
	test ! -e "$WORK/lib.upatch"
'

test_expect_success 'a header relabelled BPF is refused' '
	python3 -I - "$WORK/agent.upatch" "$WORK/bpf.upatch" <<-PY &&
	import struct, sys
	b = bytearray(open(sys.argv[1], "rb").read())
	struct.pack_into("<I", b, 352, 1)
	open(sys.argv[2], "wb").write(b)
	PY
	! "$S" upatch info "$WORK/bpf.upatch" >/dev/null 2>&1
'

command -v tar >/dev/null 2>&1 || test_done
REPO=$(cd .. && pwd)
mkdir -p "$WORK/pkg" "$WORK/keys"
cp "$WORK/agent.jar" "$WORK/pkg/agent.jar"
cp "$WORK/k.pem" "$WORK/keys/signing_key.pem"
cp "$WORK/c.der" "$WORK/keys/cert.der"
cat >"$WORK/pkg/Beefile" <<-TOML
	[package]
	name = "java-agent"
	description = "t3014"
	license = "BSD-2-Clause"

	[[upatches]]
	type = "java"
	source = "agent.jar"
TOML

test_expect_success 'bpm build packages a Java upatch and its unload' '
	( cd "$WORK" && SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build" \
		"$REPO/shirudo" bpm build pkg --version 1.0.0 \
		--keys-dir "$WORK/keys" ) >/dev/null 2>&1 &&
	tar -xOf "$WORK/java-agent-1.0.0.bee" \
		java-agent-1.0.0/upatches/agent.upatch >"$WORK/pkg.upatch" &&
	tar -xOf "$WORK/java-agent-1.0.0.bee" \
		java-agent-1.0.0/upatches/agent.unload.upatch \
		>"$WORK/pkg.unload.upatch" &&
	test "$(info "$WORK/pkg.upatch" | field payload_type)" = java &&
	test "$(info "$WORK/pkg.unload.upatch" | field payload_type)" = java &&
	test "$(info "$WORK/pkg.unload.upatch" | field unload_payload_sha256)" = \
	     "$(info "$WORK/pkg.upatch" | field payload_sha256)"
'

test_expect_success 'a Java upatch takes no rodata' '
	cat >>"$WORK/pkg/Beefile" <<-TOML &&

	[[upatches.rodata]]
	symbol = "x"
	input = "x"
	generator = ["true"]
	update = ["true"]
	TOML
	! ( cd "$WORK" && SHIRUDO_BUILD="$REPO/tools/shirudo-build/shirudo-build" \
		"$REPO/shirudo" bpm build pkg --version 1.0.1 \
		--keys-dir "$WORK/keys" ) >/dev/null 2>&1 &&
	test ! -e "$WORK/java-agent-1.0.1.bee"
'

test_done
