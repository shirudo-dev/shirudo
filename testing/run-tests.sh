#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/run-tests.sh -- discover and run every t0xxx operator test in this
# directory and its named test groups. Target tests are listed by
# run-target-tests.sh.
# CI-friendly; sets non-zero exit if any test
# fails.

set -eu

cd "$(dirname "$0")"

fail=0
found=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in t0[0-9][0-9][0-9]-*.sh; do
	[ -e "$t" ] || continue
	found=1
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

for t in otel/t0[0-9][0-9][0-9]-*.sh; do
	[ -e "$t" ] || continue
	found=1
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

for t in upatch/kernel-obs/dns/t0[0-9][0-9][0-9]-*.sh; do
	[ -e "$t" ] || continue
	found=1
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

if [ "$found" -eq 0 ]; then
	echo "# no tests yet" >&2
fi

exit "$fail"
