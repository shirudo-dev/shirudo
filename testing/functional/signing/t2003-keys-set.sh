#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t2003 -- the trusted certificate set: cert.der plus the vouched
# trusted/*.der, each public key once, revoked ones left out, and the
# digest the init event covers, which attest predict must compute the
# same way from the same certificates in any order.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
H=helper/test-keys
SHB=../tools/shirudo-build/shirudo-build
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
for k in a b c; do
	../shirudo genkey --keys-dir "$W/$k" >/dev/null 2>&1 ||
		test_skip_all "genkey failed (OpenSSL without ML-DSA?)"
done
mkdir -p "$W/keys/trusted" "$W/keys/revoked"
cp "$W/a/cert.der" "$W/keys/cert.der"
fp_b=$(../shirudo bpm key fingerprint "$W/b/cert.der" 2>/dev/null)
fp_c=$(../shirudo bpm key fingerprint "$W/c/cert.der" 2>/dev/null)
for k in b c; do
	eval "fp=\$fp_$k"
	cp "$W/$k/cert.der" "$W/keys/trusted/$fp.der"
	$SHB keys vouch "$W/$k/cert.der" -o "$W/keys/trusted/$fp.vouch" \
		--keys-dir "$W/a" >/dev/null 2>&1 ||
		test_skip_all "keys vouch failed"
done
sha() { sha256sum "$1" | cut -c1-64; }

test_expect_success 'the set holds the primary and the trusted certificates once each' '
	./$H load "$W/keys" >"$W/set" &&
	grep -qx "n=3 revoked=0 unvouched=0" "$W/set" &&
	grep -q "^$(sha "$W/a/cert.der") .* primary " "$W/set" &&
	grep -q "^$(sha "$W/b/cert.der") $fp_b trusted " "$W/set" &&
	cp "$W/a/cert.der" "$W/keys/trusted/dup.der" &&
	./$H load "$W/keys" | grep -qx "n=3 revoked=0 unvouched=0"
'

test_expect_success 'the primary alone is the single-certificate set' '
	./$H load "$W/keys" primary | grep -qx "n=1 revoked=0 unvouched=0" &&
	[ "$(./$H digest "$W/keys" primary)" = "$(sha "$W/a/cert.der")" ]
'

test_expect_success 'the set digest is order-free and attest predict agrees' '
	d=$(./$H digest "$W/keys") &&
	[ "$d" != "$(sha "$W/a/cert.der")" ] &&
	p1=$(../shirudo attest predict --cert="$W/a/cert.der" --cert="$W/b/cert.der" --cert="$W/c/cert.der" | sed -n "s/^init_event: //p") &&
	p2=$(../shirudo attest predict --cert="$W/c/cert.der" --cert="$W/a/cert.der" --cert="$W/b/cert.der" | sed -n "s/^init_event: //p") &&
	[ -n "$p1" ] && [ "$p1" = "$p2" ] &&
	p3=$(../shirudo attest predict --cert="$W/a/cert.der" | sed -n "s/^init_event: //p") &&
	[ "$p1" != "$p3" ]
'

test_expect_success 'either active key verifies an exact detached signature' '
	python3 - "$W/c/cert.der" "$W/payload" <<"PYTEST" &&
from pathlib import Path
import sys
Path(sys.argv[2]).write_bytes(b"shirudo-key-vouch\0" + Path(sys.argv[1]).read_bytes())
PYTEST
	$SHB keys vouch "$W/c/cert.der" --keys-dir "$W/a" -o "$W/signed-a" >/dev/null &&
	$SHB keys vouch "$W/c/cert.der" --keys-dir "$W/b" -o "$W/signed-b" >/dev/null &&
	./$H verify-signature "$W/keys" "$W/payload" "$W/signed-a" >"$W/verified-a" &&
	./$H verify-signature "$W/keys" "$W/payload" "$W/signed-b" >"$W/verified-b" &&
	grep -qx "$(../shirudo bpm key fingerprint "$W/a/cert.der")" "$W/verified-a" &&
	grep -qx "$fp_b" "$W/verified-b"
'

test_expect_success 'a valid signature from outside the active key set is rejected' '
	mkdir "$W/primary-only" && cp "$W/a/cert.der" "$W/primary-only/cert.der" &&
	! ./$H verify-signature "$W/primary-only" "$W/payload" "$W/signed-b" &&
	cp "$W/payload" "$W/changed-payload" && printf changed >>"$W/changed-payload" &&
	! ./$H verify-signature "$W/keys" "$W/changed-payload" "$W/signed-b"
'

test_expect_success 'a revoked certificate is left out of the set' '
	cp "$W/c/cert.der" "$W/keys/revoked/$fp_c.der" &&
	./$H load "$W/keys" >"$W/set2" &&
	grep -qx "n=2 revoked=1 unvouched=0" "$W/set2" &&
	! grep -q "$fp_c" "$W/set2"
'

test_expect_success 'malformed trusted certificates are rejected before or after valid candidates' '
	mkdir -p "$W/malformed/trusted" &&
	cp "$W/a/cert.der" "$W/malformed/cert.der" &&
	cp "$W/b/cert.der" "$W/malformed/trusted/middle.der" &&
	printf "invalid DER" >"$W/malformed/trusted/first.der" &&
	./$H reject "$W/malformed" &&
	mv "$W/malformed/trusted/first.der" "$W/malformed/trusted/last.der" &&
	mv "$W/malformed/trusted/middle.der" "$W/malformed/trusted/first.der" &&
	./$H reject "$W/malformed"
'

test_expect_success 'image revocation preserves historical vouches while excluding revoked signing keys' '
	rm "$W/keys/revoked/$fp_c.der" &&
	$SHB keys vouch "$W/c/cert.der" -o "$W/keys/trusted/$fp_c.vouch" \
		--keys-dir "$W/b" >/dev/null 2>&1 &&
	fp_a=$(../shirudo bpm key fingerprint "$W/a/cert.der" 2>/dev/null) &&
	cp "$W/a/cert.der" "$W/keys/revoked/$fp_a.der" &&
	cp "$W/b/cert.der" "$W/keys/revoked/$fp_b.der" &&
	./$H image "$W/keys" >"$W/image-set" &&
	grep -qx "n=1 revoked=2 unvouched=0" "$W/image-set" &&
	grep -q "^$(sha "$W/c/cert.der") $fp_c trusted " "$W/image-set" &&
	! grep -q "^$(sha "$W/a/cert.der") " "$W/image-set" &&
	! grep -q "^$(sha "$W/b/cert.der") " "$W/image-set"
'

test_expect_success 'revoking A leaves B signatures valid and refuses earlier A signatures' '
	rm "$W/keys/revoked/$fp_b.der" &&
	./$H verify-signature "$W/keys" "$W/payload" "$W/signed-b" >"$W/remaining" &&
	grep -qx "$fp_b" "$W/remaining" &&
	! ./$H verify-signature "$W/keys" "$W/payload" "$W/signed-a"
'


test_done
