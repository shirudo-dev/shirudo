#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ../test-lib.sh

test_expect_success 'map export configuration validates defaults and values' '
	../helper/test-config
'

test_done
