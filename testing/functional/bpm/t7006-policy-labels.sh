#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7006 -- bpm build turns Beefile policy declarations into the signed
# policy-label section consumed by upatch load.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
SHB=../tools/shirudo-build/shirudo-build
CHECK=helper/test-upatch-prog-metadata

command -v clang >/dev/null 2>&1 || test_skip_all "no clang"
command -v openssl >/dev/null 2>&1 || test_skip_all "no openssl"
command -v tar >/dev/null 2>&1 || test_skip_all "no tar"
[ -x "$S" ] || test_skip_all "shirudo not built"
[ -x "$SHB" ] || test_skip_all "shirudo-build not built"
[ -x "$CHECK" ] || test_skip_all "upatch metadata helper not built"
[ -e ../vendor/linux/vmlinux.h ] || test_skip_all "no vendor/linux/vmlinux.h"
openssl list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA' ||
	test_skip_all "openssl without ML-DSA (needs OpenSSL >= 3.5)"

REPO=$(cd .. && pwd)
S="$REPO/shirudo"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

"$S" genkey --keys-dir "$WORK/keys" >/dev/null 2>&1 ||
	test_skip_all "genkey failed"
mkdir -p "$WORK/pkg"
cp fixtures/policy-labels/Beefile \
	fixtures/policy-labels/policy-labels.bpf.c "$WORK/pkg/"
ln -s "$REPO/vendor" "$WORK/pkg/vendor"
ln -s "$REPO/bpf" "$WORK/pkg/bpf"
case "$SHB" in
/*) B="$SHB" ;;
*)  B="$REPO/${SHB#../}" ;;
esac

export SHIRUDO_BUILD="$B"
( cd "$WORK" && "$S" bpm build pkg --version 1.0.0 \
	--keys-dir "$WORK/keys" --vmlinux "$REPO/vendor/linux/vmlinux.h" ) \
	>"$WORK/build.out" 2>&1 || {
	cat "$WORK/build.out" >&2
	test_skip_all "bpm build failed"
}

test_expect_success 'Beefile policy entries are carried in the signed upatch' '
	tar -xOf "$WORK/policy-labels-1.0.0.bee" \
		policy-labels-1.0.0/upatches/policy-labels.upatch \
		>"$WORK/policy-labels.upatch" &&
	"$CHECK" "$WORK/policy-labels.upatch" policy-labels
'

test_done
