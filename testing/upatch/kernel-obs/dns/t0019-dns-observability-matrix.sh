#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../../.."
. ./test-lib.sh

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

test_expect_success 'DNS packet-case builders and batch encoding are valid' '
	python3 upatch/kernel-obs/dns/dns_obs_matrix.py --self-test
'

test_done
