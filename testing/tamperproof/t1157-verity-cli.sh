#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
work=${SHIRUDO_TEST_CLI_RESULTS:-$(mktemp -d)}
mkdir -p "$work"
export SHIRUDO_BIN

test_expect_success 'image key enrollment requires a signed config and reboot' '
	python3 tamperproof/t1157-verity-cli.py enrollment "$work"
'
test_expect_success 'image revocation and repository changes require signed config activation' '
	python3 tamperproof/t1157-verity-cli.py mutation "$work"
'
test_expect_success 'image mode keeps command help available' '
	python3 tamperproof/t1157-verity-cli.py help "$work"
'
test_done
