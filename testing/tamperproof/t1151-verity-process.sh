#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
verity_required() {
	printf 'Bail out! %s\n' "$*" >&2
	exit 1
}
target_guard

: "${SHIRUDO_TEST_RUNTIME_PROBE:=/run/shirudo/runtime/usr/bin/shirudo-policy-probe}"
[ -x "$SHIRUDO_TEST_RUNTIME_PROBE" ] ||
	verity_required "runtime image has no authority test fixture"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"

test_expect_success 'root cannot attach or write memory of an image-authorized task' '
	python3 tamperproof/t1151-verity-process.py "$SHIRUDO_TEST_RUNTIME_PROBE"
'

test_done
