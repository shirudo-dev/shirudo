#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6141 -- policy bits accumulate from the parent task, the executed file
# and every interpreter handler pass.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

PROBE=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
[ -x "$PROBE" ] || test_skip_all "runtime policy probe is missing"

WORK=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

cat >"$WORK/b.sh" <<EOF
#!$PROBE check-policy
EOF
cat >"$WORK/a.sh" <<EOF
#!$PROBE fork-exec-policy
EOF
chmod +x "$WORK/a.sh" "$WORK/b.sh"
"$PROBE" set-policy "$WORK/a.sh" 0x1 ||
	test_skip_all "scratch filesystem cannot store policy xattrs"
"$PROBE" set-policy "$WORK/b.sh" 0x2 ||
	test_skip_all "cannot set the child policy xattr"

cat >"$WORK/interpreter" <<EOF
#!$PROBE check-policy
EOF
cat >"$WORK/file.sh" <<EOF
#!$WORK/interpreter
EOF
chmod +x "$WORK/interpreter" "$WORK/file.sh"
"$PROBE" set-policy "$WORK/interpreter" 0x8 ||
	test_skip_all "cannot set the interpreter policy xattr"
"$PROBE" set-policy "$WORK/file.sh" 0x4 ||
	test_skip_all "cannot set the original file policy xattr"

test_expect_success 'A policy is inherited by B and ORed with B policy' '
	SHIRUDO_POLICY_PARENT=0x1 \
	SHIRUDO_POLICY_CHILD="$WORK/b.sh" \
	SHIRUDO_POLICY_CHILD_EXPECTED=0x3 "$WORK/a.sh"
'

test_expect_success 'original file and interpreter policies are ORed' '
	SHIRUDO_EXPECTED_POLICY=0xc "$WORK/file.sh"
'

test_done
