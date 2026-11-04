# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# Copyright (c) 2026 Authors of shirudo

: "${TEST_FILTER:=}"
while getopts 't:' opt; do
	case "$opt" in
	t) TEST_FILTER=$OPTARG ;;
	*) exit 2 ;;
	esac
done
shift "$((OPTIND - 1))"
export TEST_FILTER

printf '\n' | LC_ALL=C grep -Eq -- "$TEST_FILTER" ||
	[ "$?" -eq 1 ] || exit 2

test_matches() {
	[ -z "$TEST_FILTER" ] ||
		printf '%s\n' "${1##*/}" | LC_ALL=C grep -Eq -- "$TEST_FILTER"
}
