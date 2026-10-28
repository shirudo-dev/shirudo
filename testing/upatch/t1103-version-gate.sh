#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1103 -- version-skew gate: a load whose --expect-version-id does not
# match the target's SHIRUDO_VERSION_ID is refused with version_mismatch
# as the FIRST pre-flight check, before the .upatch is opened (so a
# nonexistent path still trips it). A matching id lets the gate pass (and
# the op then fails later for a different reason on the bogus path).
# Non-destructive.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

BOGUS="/tmp/shirudo-nonexistent-$$.upatch"

test_expect_success 'mismatched --expect-version-id -> version_mismatch' '
	cat=$($SHIRUDO_BIN upatch load "$BOGUS" \
	      --expect-version-id=deadbeefdeadbeef --no-precheck --report=- \
	      2>/dev/null | report_field category) &&
	[ "$cat" = "version_mismatch" ]
'

test_expect_success 'matching --expect-version-id passes the version gate' '
	vid=$($SHIRUDO_BIN status --json 2>/dev/null | report_field version_id) &&
	[ -n "$vid" ] &&
	cat=$($SHIRUDO_BIN upatch load "$BOGUS" --expect-version-id="$vid" \
	      --no-precheck --report=- 2>/dev/null | report_field category) &&
	[ "$cat" != "version_mismatch" ]
'

test_done
