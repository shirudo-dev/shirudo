#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

test_expect_success 'image seal builds with seccomp fields in vmlinux.h' '
	python3 helper/test-seal-seccomp.py enabled
'

test_expect_success 'image seal builds with an empty seccomp type in vmlinux.h' '
	python3 helper/test-seal-seccomp.py disabled
'

test_done
