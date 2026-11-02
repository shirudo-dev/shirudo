#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?}
PIN=/run/shirudo/bpffs/upatches/shirudo-test-loader-mixed

test_expect_success 'the signed fixture carries both attachment paths and a serializer' '
	helper/test-upatch-prog-metadata \
		"$FIXTURES/shirudo-test-loader-mixed.upatch" loader-mixed
'

test_expect_success 'loader-created and userspace-created links are pinned together' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/shirudo-test-loader-mixed.upatch" &&
	test -e "$PIN/link_0" &&
	test -e "$PIN/link_1" &&
	test -e "$PIN/serializers/events" &&
	test ! -e "$PIN/link_2"
'

test_expect_success 'a signed unload removes both kinds of links' '
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/shirudo-test-loader-mixed.unload.upatch" &&
	test ! -d "$PIN"
'

test_done
