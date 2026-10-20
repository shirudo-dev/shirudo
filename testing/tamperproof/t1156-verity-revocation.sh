#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
: "${SHIRUDO_TEST_KEY_FIXTURES:?signed key fixtures are required}"
work=${SHIRUDO_TEST_REVOKE_RESULTS:-$(mktemp -d)}
mkdir -p "$work"
export SHIRUDO_BIN SHIRUDO_TEST_KEY_FIXTURES

test_expect_success 'signed revocation fixture retains the primary and names the boot signer' '
	python3 tamperproof/t1156-verity-revocation.py initial "$work"
'
test_expect_success 'boot signer loads a pinned upatch with verified NV evidence' '
	python3 tamperproof/t1156-verity-revocation.py load "$work"
'
test_expect_success 'signed CONFIG revocation unlinks its signer and purges its measured upatch' '
	python3 tamperproof/t1156-verity-revocation.py revoke "$work"
'
test_done
