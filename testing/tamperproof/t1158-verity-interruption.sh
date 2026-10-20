#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
work=${SHIRUDO_TEST_INTERRUPTION_RESULTS:?persistent results directory required}
for command in python3 tpm2_pcrread; do
	command -v "$command" >/dev/null 2>&1 || {
		printf "Bail out! missing required interruption test tool: %s\n" "$command" >&2
		exit 1
	}
done
[ -x /run/shirudo/runtime/usr/bin/shirudo-image-fault ] || {
	printf "Bail out! trusted interruption helper is missing\n" >&2
	exit 1
}
mkdir -p "$work"
export SHIRUDO_BIN
test_expect_success 'post-measurement interruption blocks mutations and attestation' '
	python3 tamperproof/t1158-verity-interruption.py interruption "$work"
'
test_done
