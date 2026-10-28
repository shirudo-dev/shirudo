#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1104 -- unload payload_mismatch: a signed UNLOAD directive whose
# expected payload_sha256 does not match the loaded upatch's pin xattr
# is refused with category payload_mismatch and detaches nothing. The
# directive's signature still verifies (operator key); only the payload
# binding is wrong. Non-destructive: the pin survives.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
UP=shirudo-test-basic
UNLOAD="$FIXTURES/shirudo-test-basic-mismatch.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$UP/link"
[ -e "$PIN" ] || test_skip_all "basic fixture is not loaded"
[ -s "$UNLOAD" ] || test_skip_all "missing prebuilt mismatch unload fixture"

test_expect_success 'wrong expected payload -> payload_mismatch, pin intact' '
	cat=$($SHIRUDO_BIN upatch unload "$UNLOAD" --no-precheck \
	      --report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "payload_mismatch" ] &&
	[ -e "$PIN" ]
'

test_done
