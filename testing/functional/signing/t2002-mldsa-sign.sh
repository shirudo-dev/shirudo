#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t2002 -- the ML-DSA signing path end to end on the operator side:
# genkey (ML-DSA-87), build a tiny fentry upatch with it, and check the
# embedded detached CMS against the kernel's expectations (ML-DSA-87
# SignerInfo, keyid signer, no embedded cert, SHA-512 signed attributes
# without signingTime on OpenSSL 3.x) by verifying it with openssl over
# the exact loader_insns || data bytes the kernel folds. Also checks
# that the builder refuses a classical (RSA) signing key outright, and
# an ML-DSA key of a smaller parameter set than ML-DSA-87, and that the
# same signed bytes under a header that ends the loader elsewhere keep
# no signed name.
# Needs clang and shirudo-build; the ML-DSA cases need OpenSSL >= 3.5.

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
[ -e ../vendor/libbpf/bpf/bpf_helpers.h ] || test_skip_all "no vendored bpf headers"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.bpf.c" <<'BPF'
// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_nanosleep")
int BPF_PROG(t0029_fn)
{
	return 0;
}
BPF

case "$SHB" in
/*) B="$SHB" ;;
*)  B="$(pwd)/$SHB" ;;
esac

# A classical key must be refused before anything is signed, on any
# OpenSSL: the kernel-side trust anchor is ML-DSA-87 only.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/rsa.pem" \
	-outform DER -out "$WORK/rsa.der" -days 1 -sha256 -subj "/CN=t2002" \
	>/dev/null 2>&1 || test_skip_all "openssl RSA keygen failed"

test_expect_success 'shirudo-build refuses to sign with an RSA key' '
	! ( cd .. && "$B" "$WORK/t.bpf.c" -o "$WORK/rsa.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name t0029rsa --key "$WORK/rsa.pem" --cert "$WORK/rsa.der" ) \
		>"$WORK/rsa.out" 2>&1 &&
	grep -q "ML-DSA-87 only" "$WORK/rsa.out" &&
	! test -e "$WORK/rsa.upatch"
'

if ! openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA'; then
	printf '# openssl without ML-DSA (needs OpenSSL >= 3.5); signing cases not run\n'
	test_done
fi

test_expect_success 'shirudo-build refuses to sign with an ML-DSA-65 key' '
	openssl req -x509 -newkey ML-DSA-65 -nodes -keyout "$WORK/mldsa65.pem" \
		-outform DER -out "$WORK/mldsa65.der" -days 1 -subj "/CN=t2002" \
		>/dev/null 2>&1 &&
	! ( cd .. && "$B" "$WORK/t.bpf.c" -o "$WORK/mldsa65.upatch" --vmlinux vendor/linux/vmlinux.h \
		--name t0029mldsa65 --key "$WORK/mldsa65.pem" --cert "$WORK/mldsa65.der" ) \
		>"$WORK/mldsa65.out" 2>&1 &&
	grep -q "ML-DSA-65 key; shirudo signs with ML-DSA-87 only" "$WORK/mldsa65.out" &&
	! test -e "$WORK/mldsa65.upatch"
'

"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "genkey failed"
( cd .. && "$B" "$WORK/t.bpf.c" -o "$WORK/u.upatch" --vmlinux vendor/linux/vmlinux.h \
	--name t2002 --key "$WORK/keys/signing_key.pem" \
	--cert "$WORK/keys/cert.der" ) >/dev/null 2>&1 ||
	test_skip_all "build failed (clang/headers?)"

# Slice the signature and the signed bytes out of the artifact using the
# fixed v1 header offsets (Documentation/reference/formats/upatch-format.rst).
python3 - "$WORK/u.upatch" "$WORK" <<'PY'
import struct, sys
path, out = sys.argv[1], sys.argv[2]
b = open(path, "rb").read()
ioff, ilen, soff, slen = struct.unpack_from("<4I", b, 304)
doff, dlen = struct.unpack_from("<2I", b, 328)
open(out + "/sig.der", "wb").write(b[soff:soff + slen])
content = b[ioff:ioff + ilen] + (b[doff:doff + dlen] if doff else b"")
open(out + "/content.bin", "wb").write(content)
open(out + "/tampered.bin", "wb").write(content[:-1] + bytes([content[-1] ^ 1]))
open(out + "/siglen", "w").write(str(slen))
# The header is not signed: one that gives the loader's last instruction
# to the data describes the same signed bytes and the same digest.
header = bytearray(b[:360])
loader, data = content[:ilen - 8], content[ilen - 8:]
struct.pack_into("<8I", header, 304, 360, len(loader), 360 + len(content),
                 slen, 0, 0, 360 + len(loader), len(data))
open(out + "/split.upatch", "wb").write(bytes(header) + loader + data +
                                        b[soff:soff + slen])
PY
openssl x509 -inform DER -in "$WORK/keys/cert.der" -out "$WORK/cert.pem" 2>/dev/null

test_expect_success 'signature is an ML-DSA-87 SignerInfo identified by keyid, no embedded cert' '
	openssl cms -cmsout -inform DER -in "$WORK/sig.der" -print >"$WORK/cms.txt" 2>&1 &&
	grep -q "ML-DSA-87" "$WORK/cms.txt" &&
	grep -q "subjectKeyIdentifier" "$WORK/cms.txt" &&
	! grep -q "X509v3 Subject Key Identifier" "$WORK/cms.txt"
'

test_expect_success 'ML-DSA signature is larger than the old 4 KiB cap and below the 16 KiB writer cap' '
	siglen=$(cat "$WORK/siglen") &&
	[ "$siglen" -gt 4096 ] && [ "$siglen" -lt 16384 ]
'

test_expect_success 'signed attributes form (OpenSSL 3.x) uses SHA-512 and omits signingTime' '
	if grep -q "messageDigest" "$WORK/cms.txt"; then
		grep -q "sha512" "$WORK/cms.txt" && ! grep -q "signingTime" "$WORK/cms.txt"
	else
		# OpenSSL 4 signs the content directly: no attributes at all.
		! grep -q "signingTime" "$WORK/cms.txt"
	fi
'

test_expect_success 'openssl verifies the detached CMS over loader_insns || data' '
	openssl cms -verify -binary -inform DER -in "$WORK/sig.der" \
		-content "$WORK/content.bin" -certfile "$WORK/cert.pem" \
		-CAfile "$WORK/cert.pem" -purpose any -out /dev/null 2>/dev/null
'

test_expect_success 'a one-bit change in the signed bytes is rejected' '
	! openssl cms -verify -binary -inform DER -in "$WORK/sig.der" \
		-content "$WORK/tampered.bin" -certfile "$WORK/cert.pem" \
		-CAfile "$WORK/cert.pem" -purpose any -out /dev/null 2>/dev/null
'

test_expect_success 'the signed bytes split after another instruction keep no signed name' '
	"$S" upatch info "$WORK/u.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d[\"signed_name\"] == \"t2002\", d.get(\"signed_name\")
print(d[\"payload_sha256\"], d[\"loader_insns_len\"] - 8, d[\"data_len\"] + 8)
" >"$WORK/signed" &&
	"$S" upatch info "$WORK/split.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d[\"signed_name\"] is None, d.get(\"signed_name\")
assert d[\"attach_metadata_len\"] == 0, d.get(\"attach_metadata_len\")
print(d[\"payload_sha256\"], d[\"loader_insns_len\"], d[\"data_len\"])
" >"$WORK/split" &&
	cmp "$WORK/signed" "$WORK/split"
'

test_expect_success 'upatch info --json reports the artifact and signature length' '
	"$S" upatch info "$WORK/u.upatch" --json 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d[\"name\"] == \"t2002\", d.get(\"name\")
assert d[\"signature_len\"] > 4096, d.get(\"signature_len\")
"
'

test_done
