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

: "${SHIRUDO_TEST_RUNTIME_BIN:=/run/shirudo/runtime/usr/bin/shirudo}"
mountpoint -q /run/shirudo/runtime && [ -x "$SHIRUDO_TEST_RUNTIME_BIN" ] ||
	verity_required "requires the executable from the runtime image"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"

test_expect_success 'hidden bpffs cannot make an image executable initialize legacy state' '
	python3 tamperproof/t1153-verity-hidden.py "$SHIRUDO_TEST_RUNTIME_BIN"
'

test_done
