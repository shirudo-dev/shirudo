#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
MOCK=$WORK/testing
mkdir -p "$MOCK/functional/build" "$MOCK/functional/sample"
cp run-tests.sh run-target-tests.sh test-filter.sh "$MOCK/"
printf 'echo alpha\n' >"$MOCK/functional/build/t1001-alpha.sh"
printf 'echo beta\n' >"$MOCK/functional/build/t1002-beta.sh"
printf 'echo other\n' >"$MOCK/functional/build/t1003-other.sh"
touch "$MOCK/functional/sample/t9101-alpha.sh"

test_expect_success '-t supports anchors and alternation over script basenames' '
	sh "$MOCK/run-tests.sh" -t "^t100(1|2)-(alpha|beta)\.sh$" functional/build \
		>"$WORK/operator.out" &&
	printf "alpha\nbeta\n" >"$WORK/expected" &&
	cmp "$WORK/expected" "$WORK/operator.out"
'

test_expect_success 'TEST_FILTER selects scripts for make-driven runs' '
	TEST_FILTER=alpha sh "$MOCK/run-tests.sh" functional/build \
		>"$WORK/operator.out" &&
	printf "alpha\n" >"$WORK/expected" &&
	cmp "$WORK/expected" "$WORK/operator.out"
'

test_expect_success '-t overrides the environment filter' '
	TEST_FILTER=other sh "$MOCK/run-tests.sh" -t alpha functional/build \
		>"$WORK/operator.out" &&
	printf "alpha\n" >"$WORK/expected" &&
	cmp "$WORK/expected" "$WORK/operator.out"
'

test_expect_success 'an empty pattern selects every script in order' '
	sh "$MOCK/run-tests.sh" -t "" functional/build >"$WORK/operator.out" &&
	printf "alpha\nbeta\nother\n" >"$WORK/expected" &&
	cmp "$WORK/expected" "$WORK/operator.out"
'

test_expect_success 'a pattern with no matches executes no scripts' '
	sh "$MOCK/run-tests.sh" -t "^missing$" functional/build \
		>"$WORK/operator.out" &&
	[ ! -s "$WORK/operator.out" ]
'

test_expect_success 'the target runner parses -t before checking target setup' '
	! SHIRUDO_BIN= sh "$MOCK/run-target-tests.sh" -t alpha sample \
		>"$WORK/target.out" 2>&1 &&
	grep -q "runtime command is required" "$WORK/target.out"
'

test_expect_success 'both runners reject invalid expressions and missing -t arguments' '
	for runner in run-tests.sh run-target-tests.sh; do
		for pattern in "[" "("; do
			ret=0
			sh "$MOCK/$runner" -t "$pattern" \
				>"$WORK/invalid.out" 2>&1 || ret=$?
			[ "$ret" -eq 2 ] || return 1
		done
		ret=0
		sh "$MOCK/$runner" -t >"$WORK/invalid.out" 2>&1 || ret=$?
		[ "$ret" -eq 2 ] || return 1
	done
'

test_expect_success 'a selected failing script still fails the runner' '
	printf "exit 7\n" >"$MOCK/functional/build/t1003-other.sh" &&
	ret=0 &&
	{ sh "$MOCK/run-tests.sh" -t other functional/build || ret=$?; } &&
	[ "$ret" -eq 1 ]
'

test_done
