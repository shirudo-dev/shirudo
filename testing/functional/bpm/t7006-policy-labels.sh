#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7006 -- bpm build turns Beefile policy declarations into the signed
# policy-label section consumed by upatch load, a pattern as it is
# written, and refuses a path that is none.

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
test_expect_success 'bpm build packages the policy-labeled upatch' '
	( cd "$WORK" && "$S" bpm build pkg --version 1.0.0 \
		--keys-dir "$WORK/keys" \
		--vmlinux "$REPO/vendor/linux/vmlinux.h" ) >&2 &&
	test -s "$WORK/policy-labels-1.0.0.bee"
'
[ -s "$WORK/policy-labels-1.0.0.bee" ] || test_done

test_expect_success 'Beefile policy entries are carried in the signed upatch' '
	tar -xOf "$WORK/policy-labels-1.0.0.bee" \
		policy-labels-1.0.0/upatches/policy-labels.upatch \
		>"$WORK/policy-labels.upatch" &&
	"$CHECK" "$WORK/policy-labels.upatch" policy-labels
'

# Build the fixture with $1 in place of the path of its pattern.
build_with_path() {
	rm -rf "$WORK/bad" &&
	mkdir "$WORK/bad" &&
	cp -P "$WORK/pkg/"* "$WORK/bad/" &&
	sed "s|/tmp/shirudo-policy-label-test/match-\*|$1|" \
		fixtures/policy-labels/Beefile >"$WORK/bad/Beefile" &&
	grep -qF "\"$1\"" "$WORK/bad/Beefile" &&
	( cd "$WORK" && "$S" bpm build bad --version 1.0.0 \
		--keys-dir "$WORK/keys" \
		--vmlinux "$REPO/vendor/linux/vmlinux.h" ) 2>"$WORK/bad.err"
}

test_expect_success 'bpm build takes a wildcard in the last component of a path alone' '
	build_with_path "/tmp/shirudo-policy-label-test/m?tch*" >&2 &&
	for path in "/tmp/*/match" "/tmp/shirudo-policy-label-?est/match-*" \
		"/tmp/shirudo-policy-label-test/" "tmp/match"; do
		! build_with_path "$path" &&
		grep -q "is not a valid Beefile" "$WORK/bad.err" || return 1
	done
'

test_done
