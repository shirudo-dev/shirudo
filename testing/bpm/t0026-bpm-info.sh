#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}

test_expect_success 'bpm info prints local and OCI READMEs without installing' '
	python3 helper/test-bpm-info.py "$SHIRUDO"
'

test_done
