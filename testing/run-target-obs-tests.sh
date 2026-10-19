#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

cd "$(dirname "$0")"

fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for test_script in \
	upatch/kernel-obs/network/t1210-kernel-obs.sh \
	upatch/kernel-obs/priv/kernel-obs-priv.sh \
	upatch/kernel-obs/dns/t1211-kernel-obs-dns-matrix.sh
do
	if sh "$test_script"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$test_script" \
				>>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

exit "$fail"
