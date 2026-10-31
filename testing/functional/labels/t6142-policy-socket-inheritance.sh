#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6142 -- task policy follows a listener into accepted sockets.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

PROBE=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
[ -x "$PROBE" ] || test_skip_all "runtime policy probe is missing"

WORK=$(mktemp -d) || test_skip_all "cannot make a scratch directory"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

cat >"$WORK/socket-test" <<EOF
#!$PROBE socket-inherit
EOF
chmod +x "$WORK/socket-test"
"$PROBE" set-policy "$WORK/socket-test" 0x1 ||
	test_skip_all "scratch filesystem cannot store policy xattrs"

test_expect_success 'listener policy is cloned to accepted socket' '
	"$WORK/socket-test"
'

test_done
