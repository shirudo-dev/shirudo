#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

SHIRUDO=${SHIRUDO:-../shirudo}

command -v python3 >/dev/null 2>&1 || test_skip_all 'python3 unavailable'
command -v openssl >/dev/null 2>&1 || test_skip_all 'openssl unavailable'

test_expect_success 'bpm keys fingerprint certificates, packages, and OCI references' '
	python3 helper/test-bpm-key.py "$SHIRUDO"
'

test_done
