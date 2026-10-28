#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0048 -- the tamper points are the one enum the LSM counts with and
# status names them from (bpf/lib/shirudo_tamper.h), and a counter is
# only as good as its name; this keeps every member in the table of
# names and meanings util/tamper.c holds. Also checks that status
# reports the counters as absent, not as an error, where init has not
# run.

cd "$(dirname "$0")/.."
. ./test-lib.sh

S=../shirudo
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

test_expect_success 'every point has a name and a meaning' '
	sed -n "s/^\tSHIRUDO_TAMPER_\([A-Z_]*\),$/\1/p" \
		../bpf/lib/shirudo_tamper.h >"$W/points" &&
	sed -n "s/^\t\[SHIRUDO_TAMPER_\([A-Z_]*\)\] = { \"[A-Za-z]*\",$/\1/p" \
		../util/tamper.c >"$W/table" &&
	[ -s "$W/points" ] &&
	cmp "$W/points" "$W/table"
'

test_expect_success 'status --json reports the counters as null without init' '
	if [ -e /run/shirudo/bpffs/tamper ]; then
		echo "skipping: a tamper map is pinned on this host"
	else
		"$S" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert \"tamper_attempts\" in d and d[\"tamper_attempts\"] is None
"
	fi
'

test_done
