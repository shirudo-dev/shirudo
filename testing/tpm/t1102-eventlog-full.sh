#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1102 -- eventlog cap: with eventlog.max_bytes set tiny in
# shirudo.conf, a valid load refuses with category eventlog_full at
# pre-flight. No BPF_PROG_LOAD, no chain extend, no append. Non-destructive.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REAL="$FIXTURES/shirudo-test-lifecycle.upatch"
[ -s "$REAL" ] || test_skip_all "missing lifecycle fixture"

CONF=/etc/shirudo/shirudo.conf
SAVED=$(mktemp)
if [ -e "$CONF" ]; then HAD=yes; cp "$CONF" "$SAVED"; else HAD=no; fi
cleanup() {
	if [ "$HAD" = yes ]; then cp "$SAVED" "$CONF"; else rm -f "$CONF"; fi
	rm -f "$SAVED"
}
trap cleanup EXIT
mkdir -p /etc/shirudo
printf 'eventlog.max_bytes = 100\n' > "$CONF"

test_expect_success 'tiny eventlog cap -> category eventlog_full' '
	cat=$($SHIRUDO_BIN upatch load "$REAL" --no-precheck --report=- \
	      2>/dev/null | report_field category) &&
	[ "$cat" = "eventlog_full" ]
'

test_done
