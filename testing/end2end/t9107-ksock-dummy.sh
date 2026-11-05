#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
LOAD=$FIXTURES/ksock-dummy.upatch
UNLOAD=$FIXTURES/ksock-dummy.unload.upatch
PIN=/run/shirudo/bpffs/upatches/ksock-dummy/test

cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" || true
	fi
}
trap cleanup EXIT

test_expect_success 'signed ksock sender connects and sends at load' '
	"$SHIRUDO_BIN" upatch load "$LOAD" &&
	[ -e "$PIN" ]
'

test_expect_success 'signed unload removes the ksock sender' '
	[ -e "$PIN" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" &&
	[ ! -e "$PIN" ]
'

test_done
