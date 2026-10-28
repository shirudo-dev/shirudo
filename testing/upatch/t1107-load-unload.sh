#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1107 -- load/unload happy path using a host-built fixture.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
WORK=$(mktemp -d)

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing lifecycle fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing lifecycle unload fixture"

test_expect_success 'load attaches, pins, and shows the upatch loaded' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		>/dev/null 2>&1 &&
	[ -e "$PIN" ] &&
	"$SHIRUDO_BIN" upatch list 2>/dev/null | grep -q "$NAME"
'

test_expect_success 'the pin dir carries the payload_sha256 xattr from load' '
	x=$(python3 -c "import os,sys;print(os.getxattr(sys.argv[1],\"security.bpf.shirudo.payload\").hex())" "$PINDIR" 2>/dev/null) &&
	payload=$("$SHIRUDO_BIN" upatch info "$LOAD" --json | report_field payload_sha256) &&
	[ "$x" = "$payload" ]
'

test_expect_success 'a correctly-bound UNLOAD directive detaches + removes the pin' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
		>/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
