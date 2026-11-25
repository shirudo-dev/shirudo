#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

test_expect_success 'runtime ELF closure, fixed entry and negative native links' '
	python3 ./test-runtime-packaging.py
'

test_done
