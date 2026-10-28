#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh
H=${SHIRUDO_TEST_IMAGE_KEYS_HELPER:-$(pwd)/helper/test-image-keys}
SHB=../tools/shirudo-build/shirudo-build
[ -x "$H" ] || test_skip_all "test-image-keys helper not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT HUP INT TERM

for key in a b c; do
	../shirudo genkey --keys-dir "$W/$key" >/dev/null 2>&1 || {
		test_expect_success "image key fixture generation" false
		test_done
	}
	eval "fp_$key=$(../shirudo bpm key fingerprint "$W/$key/cert.der" 2>/dev/null)"
done

fresh() {
	mkdir -p "$W/$1/etc/shirudo" "$W/$1/keys/trusted" "$W/$1/keys/revoked" &&
	printf "eventlog.max_bytes = 0\n" >"$W/$1/etc/shirudo/shirudo.conf"
}

valid() {
	"$H" "$W/a/cert.der" "$W/$1" >"$W/result" &&
	grep -q "rc=0 mutations=0" "$W/result"
}

invalid() {
	! "$H" "$W/a/cert.der" "$W/$1" >"$W/result" &&
	grep -q "mutations=0" "$W/result"
}

vouch() {
	cp "$W/$2/cert.der" "$W/$1/keys/trusted/$3.der" &&
	"$SHB" keys vouch "$W/$2/cert.der" \
		-o "$W/$1/keys/trusted/$3.vouch" --keys-dir "$W/$4" >/dev/null 2>&1
}

test_expect_success 'a config with only the authenticated initial signer passes without mutation' '
	fresh initial && valid initial && grep -q "signers=1" "$W/result"
'

test_expect_success 'a vouched boot signer and canonical revocation pass validation' '
	fresh replacement && vouch replacement b "$fp_b" a &&
	cp "$W/a/cert.der" "$W/replacement/keys/revoked/$fp_a.der" &&
	valid replacement && grep -q "signers=1" "$W/result"
'

test_expect_success 'revoked historical signers still validate earlier vouches' '
	fresh historical && vouch historical b "$fp_b" a &&
	vouch historical c "$fp_c" b &&
	cp "$W/a/cert.der" "$W/historical/keys/revoked/$fp_a.der" &&
	cp "$W/b/cert.der" "$W/historical/keys/revoked/$fp_b.der" &&
	valid historical && grep -q "signers=1" "$W/result"
'

test_expect_success 'revoking every admitted signer fails preflight' '
	fresh all-revoked &&
	cp "$W/a/cert.der" "$W/all-revoked/keys/revoked/$fp_a.der" &&
	invalid all-revoked
'

test_expect_success 'an uppercase revocation cannot bypass the last-signer check' '
	fresh uppercase && upper=$(printf %s "$fp_a" | tr a-f A-F) &&
	cp "$W/a/cert.der" "$W/uppercase/keys/revoked/$upper.der" &&
	invalid uppercase
'

test_expect_success 'a canonical filename with the wrong certificate fails preflight' '
	fresh mismatch &&
	cp "$W/b/cert.der" "$W/mismatch/keys/revoked/$fp_a.der" &&
	invalid mismatch
'

test_expect_success 'malformed DER fails even when another signer remains' '
	fresh malformed && vouch malformed b "$fp_b" a &&
	printf "not a certificate" >"$W/malformed/keys/revoked/$fp_a.der" &&
	invalid malformed
'

test_expect_success 'empty and oversized revocation records fail preflight' '
	fresh empty && : >"$W/empty/keys/revoked/$fp_a.der" && invalid empty &&
	fresh oversized && truncate -s 1048577 "$W/oversized/keys/revoked/$fp_a.der" &&
	invalid oversized
'

test_expect_success 'unknown revocation files and malformed names fail preflight' '
	for name in README bad.der abc.DE R.der; do
		fresh "unknown-$name" &&
		cp "$W/a/cert.der" "$W/unknown-$name/keys/revoked/$name" &&
		invalid "unknown-$name" || exit 1
	done
'

test_expect_success 'revocation symlinks cannot read mutable outside certificates' '
	fresh symlink &&
	ln -s "$W/a/cert.der" "$W/symlink/keys/revoked/$fp_a.der" &&
	invalid symlink
'

test_expect_success 'revocation FIFOs and directories fail without blocking' '
	fresh fifo && mkfifo "$W/fifo/keys/revoked/$fp_a.der" && invalid fifo &&
	fresh directory && mkdir "$W/directory/keys/revoked/$fp_a.der" &&
	invalid directory
'

test_expect_success 'a symlinked keys directory cannot escape the image' '
	fresh keys-link && rm -r "$W/keys-link/keys" &&
	ln -s "$W/replacement/keys" "$W/keys-link/keys" && invalid keys-link
'

test_expect_success 'an unvouched additional signer is refused before mutation' '
	fresh unvouched && cp "$W/b/cert.der" "$W/unvouched/keys/trusted/$fp_b.der" &&
	invalid unvouched
'

test_expect_success 'a corrupt vouch is refused before mutation' '
	fresh bad-vouch && vouch bad-vouch b "$fp_b" a &&
	printf "bad vouch" >"$W/bad-vouch/keys/trusted/$fp_b.vouch" && invalid bad-vouch
'

test_expect_success 'malformed additional certificates fail before mutation' '
	fresh bad-trusted && printf "invalid DER" >"$W/bad-trusted/keys/trusted/$fp_b.der" &&
	invalid bad-trusted
'

test_expect_success 'a live config with a new signer fails before PCR measurement or activation' '
	fresh new-live && vouch new-live b "$fp_b" a &&
	mkdir -m 700 "$W/new-journal" &&
	! "$H" "$W/a/cert.der" "$W/new-live" "$W/new-journal" \
		"$W/a/cert.der" >"$W/result" &&
	grep -q "extends=0 activations=0" "$W/result" &&
	grep -q "rc=-126 mutations=0" "$W/result"
'

test_expect_success 'a live config using boot-enrolled signers measures and activates' '
	mkdir -m 700 "$W/existing-journal" &&
	"$H" "$W/a/cert.der" "$W/new-live" "$W/existing-journal" \
		"$W/a/cert.der" "$W/b/cert.der" >"$W/result" &&
	grep -q "extends=1 activations=1" "$W/result" &&
	grep -q "rc=0 mutations=0" "$W/result"
'

test_expect_success 'an interrupted enrolled-key config refuses same-boot completion' '
	mkdir -m 700 "$W/pending-journal" &&
	! SHIRUDO_TEST_IMAGE_INTERRUPT=1 "$H" "$W/a/cert.der" "$W/new-live" \
		"$W/pending-journal" "$W/a/cert.der" "$W/b/cert.der" >"$W/result" &&
	grep -q "extends=1 activations=1" "$W/result" &&
	grep -q "rc=-5 mutations=0" "$W/result"
'

test_done
