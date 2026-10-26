#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0039 -- which key signed a upatch: the CMS signer identification a
# revocation purges the archive by names the signing certificate and
# no other, and a revoke event predicts the same digest the target
# measures.

cd "$(dirname "$0")/.."
. ./test-lib.sh
S=../shirudo
SHB=../tools/shirudo-build/shirudo-build
H=helper/test-keys
command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built (make shirudo-build)"
[ -x "$H" ] || test_skip_all "test-keys helper not built (make test-helpers)"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
for k in a b; do
	$S genkey --keys-dir "$W/$k" >/dev/null 2>&1 ||
		test_skip_all "genkey failed (OpenSSL without ML-DSA?)"
done
# The helper finds the vendored headers from the checkout root.
(cd .. && tools/shirudo-build/shirudo-build testing/fixtures/basic.bpf.c \
	-o "$W/basic.upatch" --name t0039-basic --vmlinux vendor/linux/vmlinux.h \
	--keys-dir "$W/a") >/dev/null 2>&1 ||
	test_skip_all "cannot build the fixture upatch"
sha() { sha256sum "$1" | cut -c1-64; }
fp_a=$($S bpm key fingerprint "$W/a/cert.der" 2>/dev/null)

test_expect_success 'the signer check names the signing certificate only' '
	[ "$(./$H signer "$W/basic.upatch" "$W/a/cert.der")" = yes ] &&
	[ "$(./$H signer "$W/basic.upatch" "$W/b/cert.der")" = no ]
'

test_expect_success 'a revoke event is predictable from the certificate digest' '
	base=$($S attest predict --cert="$W/a/cert.der" --cert="$W/b/cert.der" | sed -n "s/^register_at_boot: //p") &&
	after=$($S attest predict --cert="$W/a/cert.der" --cert="$W/b/cert.der" --event="revoke:$fp_a=$(sha "$W/a/cert.der")" | sed -n "s/^register_after_events: //p") &&
	[ -n "$base" ] && [ -n "$after" ] && [ "$base" != "$after" ] &&
	again=$($S attest predict --cert="$W/a/cert.der" --cert="$W/b/cert.der" --event="revoke:$fp_a=$(sha "$W/a/cert.der")" | sed -n "s/^register_after_events: //p") &&
	[ "$after" = "$again" ]
'

test_expect_success 'revoke refuses to run where no bpf keyring anchor is frozen' '
	! $S keys revoke "$fp_a" >/dev/null 2>&1 &&
	! $S keys revoke not-a-fingerprint >/dev/null 2>&1
'

test_done
