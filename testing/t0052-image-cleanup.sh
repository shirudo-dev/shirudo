#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

H=${SHIRUDO_TEST_IMAGE_CLEANUP_HELPER:-./helper/test-image-cleanup}
if [ ! -x "$H" ]; then
	printf "not ok 1 - test-image-cleanup helper is required\n1..1\n"
	exit 1
fi

test_expect_success 'candidate removal succeeds without a retry or delay' '
	"$H" immediate
'

test_expect_success 'candidate removal retries transient EBUSY synchronously' '
	"$H" transient
'

test_expect_success 'persistent EBUSY stops after 100 attempts and 99 delays' '
	"$H" persistent
'

test_expect_success 'candidate removal returns an I/O error immediately' '
	"$H" io
'

test_expect_success 'candidate removal returns a permission error immediately' '
	"$H" permission
'

test_done
