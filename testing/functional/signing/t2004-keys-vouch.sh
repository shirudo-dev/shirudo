#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t2004 -- vouching for a certificate: `keys vouch` signs with the
# operator key, `keys add` admits a certificate only with a vouch that
# verifies under a member of the set, and the loader admits nothing
# dropped in without one and refuses a set with a classical certificate.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
S=../shirudo
SHB=../tools/shirudo-build/shirudo-build
H=helper/test-keys
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$H" ] || test_skip_all "test-keys helper not built (make test-helpers)"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
export SHIRUDO_BUILD=$SHB
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
for k in a b c d; do
	$S genkey --keys-dir "$W/$k" >/dev/null 2>&1 ||
		test_skip_all "genkey failed (OpenSSL without ML-DSA?)"
done
mkdir -p "$W/keys"
cp "$W/a/cert.der" "$W/keys/cert.der"
fp() { $S bpm key fingerprint "$1" 2>/dev/null; }
fp_a=$(fp "$W/a/cert.der")
fp_b=$(fp "$W/b/cert.der")
fp_c=$(fp "$W/c/cert.der")
fp_d=$(fp "$W/d/cert.der")

test_expect_success 'vouch writes <cert>.vouch beside the certificate and prints its fingerprint' '
	out=$($S keys vouch "$W/b/cert.der" --keys-dir "$W/a" 2>/dev/null) &&
	[ "$out" = "$fp_b" ] &&
	[ -s "$W/b/cert.der.vouch" ] &&
	$S keys vouch "$W/c/cert.der" --keys-dir "$W/a" -o "$W/c.vouch" >/dev/null 2>&1 &&
	[ -s "$W/c.vouch" ]
'

test_expect_success 'a key cannot vouch for its own certificate' '
	! $S keys vouch "$W/a/cert.der" --keys-dir "$W/a" >/dev/null 2>&1 &&
	! [ -e "$W/a/cert.der.vouch" ]
'

test_expect_success 'add admits a certificate the primary vouched for' '
	out=$($S keys add "$W/b/cert.der" --vouch "$W/b/cert.der.vouch" --keys-dir "$W/keys" 2>/dev/null) &&
	[ "$out" = "$fp_b" ] &&
	cmp -s "$W/b/cert.der" "$W/keys/trusted/$fp_b.der" &&
	cmp -s "$W/b/cert.der.vouch" "$W/keys/trusted/$fp_b.vouch" &&
	./$H load "$W/keys" | grep -qx "n=2 revoked=0 unvouched=0" &&
	$S keys --keys-dir "$W/keys" 2>/dev/null | grep -q "vouched by $fp_a"
'

test_expect_success 'add is idempotent' '
	out=$($S keys add "$W/b/cert.der" --vouch "$W/b/cert.der.vouch" --keys-dir "$W/keys" 2>/dev/null) &&
	[ "$out" = "$fp_b" ] &&
	./$H load "$W/keys" | grep -qx "n=2 revoked=0 unvouched=0"
'

test_expect_success 'add refuses a vouch made for another certificate' '
	! $S keys add "$W/c/cert.der" --vouch "$W/b/cert.der.vouch" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	! [ -e "$W/keys/trusted/$fp_c.der" ]
'

test_expect_success 'add refuses a vouch by a key outside the set' '
	$S keys vouch "$W/c/cert.der" --keys-dir "$W/d" -o "$W/c-by-d.vouch" >/dev/null 2>&1 &&
	! $S keys add "$W/c/cert.der" --vouch "$W/c-by-d.vouch" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	! [ -e "$W/keys/trusted/$fp_c.der" ]
'

test_expect_success 'add refuses a damaged vouch' '
	head -c 100 "$W/c.vouch" >"$W/c-short.vouch" &&
	! $S keys add "$W/c/cert.der" --vouch "$W/c-short.vouch" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	! $S keys add "$W/c/cert.der" --vouch "$W/c/cert.der" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	! [ -e "$W/keys/trusted/$fp_c.der" ]
'

test_expect_success 'a member other than the primary can vouch' '
	$S keys vouch "$W/c/cert.der" --keys-dir "$W/b" -o "$W/c-by-b.vouch" >/dev/null 2>&1 &&
	$S keys add "$W/c/cert.der" --vouch "$W/c-by-b.vouch" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	./$H load "$W/keys" | grep -qx "n=3 revoked=0 unvouched=0" &&
	$S keys --keys-dir "$W/keys" 2>/dev/null | grep -q "vouched by $fp_b"
'

test_expect_success 'a certificate dropped in without a vouch is not a member' '
	cp "$W/d/cert.der" "$W/keys/trusted/$fp_d.der" &&
	./$H load "$W/keys" | grep -qx "n=3 revoked=0 unvouched=1" &&
	! ./$H load "$W/keys" | grep -q "$fp_d" &&
	cp "$W/c-by-d.vouch" "$W/keys/trusted/$fp_d.vouch" &&
	./$H load "$W/keys" | grep -qx "n=3 revoked=0 unvouched=1" &&
	rm -f "$W/keys/trusted/$fp_d.der" "$W/keys/trusted/$fp_d.vouch"
'

# keys vouch refuses a classical certificate, so openssl makes the vouch:
# the loader must refuse what an ML-DSA-87 member signed for one.
test_expect_success 'a classical certificate a member vouched for refuses the set' '
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$W/ec.pem" -outform DER -out "$W/ec.der" -days 1 \
		-subj "/CN=t2004" >/dev/null 2>&1 &&
	fp_ec=$(fp "$W/ec.der") &&
	{ printf "shirudo-key-vouch\0"; cat "$W/ec.der"; } >"$W/ec.payload" &&
	openssl cms -sign -binary -md sha512 -in "$W/ec.payload" \
		-signer "$W/a/cert.der" -inkey "$W/a/signing_key.pem" \
		-outform DER -out "$W/ec.vouch" -nosmimecap -nocerts -keyid &&
	cp "$W/ec.der" "$W/keys/trusted/$fp_ec.der" &&
	cp "$W/ec.vouch" "$W/keys/trusted/$fp_ec.vouch" &&
	! ./$H load "$W/keys" >"$W/ec.out" 2>&1 &&
	grep -q "$fp_ec.der is EC; shirudo accepts only ML-DSA-87" "$W/ec.out" &&
	rm -f "$W/keys/trusted/$fp_ec.der" "$W/keys/trusted/$fp_ec.vouch" &&
	./$H load "$W/keys" | grep -qx "n=3 revoked=0 unvouched=0"
'

test_expect_success 'image admission checks a vouched signer before applying revocations' '
	fp_ec=$(fp "$W/ec.der") &&
	cp -R "$W/keys" "$W/image-keys" &&
	mkdir -p "$W/image-keys/revoked" &&
	cp "$W/ec.der" "$W/image-keys/trusted/$fp_ec.der" &&
	cp "$W/ec.vouch" "$W/image-keys/trusted/$fp_ec.vouch" &&
	cp "$W/ec.der" "$W/image-keys/revoked/$fp_ec.der" &&
	! ./$H image "$W/image-keys" >"$W/image.out" 2>&1 &&
	grep -q "$fp_ec.der is EC; shirudo accepts only ML-DSA-87" "$W/image.out" &&
	rm "$W/image-keys/trusted/$fp_ec.der" "$W/image-keys/trusted/$fp_ec.vouch" &&
	./$H image "$W/image-keys" | grep -qx "n=3 revoked=1 unvouched=0"
'

test_expect_success 'a classical primary certificate refuses the set' '
	mkdir -p "$W/ec-primary" &&
	cp "$W/ec.der" "$W/ec-primary/cert.der" &&
	! ./$H load "$W/ec-primary" >"$W/ec-primary.out" 2>&1 &&
	grep -q "ec-primary/cert.der is EC; shirudo accepts only ML-DSA-87" \
		"$W/ec-primary.out"
'

test_expect_success 'add refuses a revoked certificate however well vouched' '
	mkdir -p "$W/keys/revoked" &&
	cp "$W/d/cert.der" "$W/keys/revoked/$fp_d.der" &&
	$S keys vouch "$W/d/cert.der" --keys-dir "$W/a" -o "$W/d.vouch" >/dev/null 2>&1 &&
	! $S keys add "$W/d/cert.der" --vouch "$W/d.vouch" --keys-dir "$W/keys" >/dev/null 2>&1 &&
	! [ -e "$W/keys/trusted/$fp_d.der" ]
'

test_expect_success 'add needs a primary certificate to extend' '
	mkdir -p "$W/empty" &&
	! $S keys add "$W/b/cert.der" --vouch "$W/b/cert.der.vouch" --keys-dir "$W/empty" >/dev/null 2>&1 &&
	! [ -d "$W/empty/trusted" ]
'

test_done
