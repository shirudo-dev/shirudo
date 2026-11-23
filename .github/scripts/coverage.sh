#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

cd "$(git rev-parse --show-toplevel)"
mkdir -p coverage

capture() {
	suffix=$1
	shift

	# VM state under build/ may be inaccessible and holds no host counters.
	# Helpers write production counters alongside the linked objects.
	for dir in \
		. \
		util \
		tools/shirudo-build \
		tools/quote-check \
		build/unit \
		build/quote-check/util \
		build/quote-check/tools/quote-check
	do
		for profile in "$dir"/*."$suffix"; do
			[ -f "$profile" ] || continue
			set -- "$@" --directory "$dir"
			break
		done
	done
	lcov --capture --no-recursion "$@"
}

capture gcno --initial --output-file coverage/baseline.lcov
capture gcda --output-file coverage/run.lcov
# Optimized code can give gcov different hit counts for a function and its lines.
lcov --ignore-errors inconsistent \
	--add-tracefile coverage/baseline.lcov --add-tracefile coverage/run.lcov \
	--output-file coverage/combined.lcov
lcov --ignore-errors inconsistent \
	--extract coverage/combined.lcov "$PWD/*" --output-file coverage/repo.lcov
lcov --ignore-errors inconsistent,unused \
	--remove coverage/repo.lcov '*/testing/*' '*/vendor/*' '*/build/*' \
	'*/util/version_id.c' --output-file coverage/host.lcov
