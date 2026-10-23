#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh
H=helper/test-harden
W=$(mktemp -d) || exit 1
trap 'rm -f "$W/out" "$W/error"; rmdir "$W"' EXIT HUP INT TERM

test_expect_success 'startup locks current and future mappings and preserves hardening' '
	./$H success | grep -qx "rc=0"
'

test_expect_success 'denied memory locking is reported and fails closed' '
	! ./$H denied >"$W/out" 2>"$W/error" &&
	grep -qx "rc=-1" "$W/out" &&
	grep -q "^hardening: cannot lock process memory:" "$W/error"
'

test_expect_success 'exhausted memory-lock limits are reported and fail closed' '
	! ./$H limit >"$W/out" 2>"$W/error" &&
	grep -qx "rc=-12" "$W/out" &&
	grep -q "^hardening: cannot lock process memory:" "$W/error"
'

test_expect_success 'all shipped services allow process-wide memory locking' '
	missing=0 &&
	for unit in ../systemd/*.service.in; do
		grep -qx "LimitMEMLOCK=infinity" "$unit" || missing=1
	done &&
	[ "$missing" -eq 0 ]
'

test_done
