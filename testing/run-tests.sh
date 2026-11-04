#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/run-tests.sh [-t <regex>] [unit[/<suite>]|ci-checks|functional[/<family>]|end2end]...
# -- the tests of each tier named, all of them without an argument, that
# run on the build host: the unit tests and the operator tests (t?0??) in
# number order. The target tests run in the test VM through
# run-target-tests.sh. CI-friendly; the exit status counts the suites that
# failed.

set -eu

cd "$(dirname "$0")"
. ./test-filter.sh

[ $# -gt 0 ] || set -- unit ci-checks functional end2end
units=
dirs=
for what; do
	case "$what" in
	unit) units="$units ../build/unit/*" ;;
	unit/*) units="$units ../build/unit/${what#unit/}" ;;
	functional) dirs="$dirs functional/*" ;;
	*) dirs="$dirs $what" ;;
	esac
	[ "$what" = unit ] || [ -e "$what" ] || [ -e "../build/$what" ] || {
		printf 'no tests %s\n' "$what" >&2
		exit 2
	}
done

unit_tests()
{
	for t in $units; do
		[ -f "$t" ] && [ -x "$t" ] && printf '%s\n' "$t"
	done
}

operator_tests()
{
	for d in $dirs; do
		for t in "$d"/t*.sh; do
			case "${t##*/}" in
			t[0-9]0[0-9][0-9]-*.sh) printf '%s %s\n' "${t##*/}" "$t" ;;
			esac
		done
	done | sort | cut -d' ' -f2
}

fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in $(unit_tests) $(operator_tests); do
	test_matches "$t" || continue
	case "$t" in
	*.sh) set -- sh "$t" ;;
	*) set -- "$t" ;;
	esac
	if "$@"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

exit "$fail"
