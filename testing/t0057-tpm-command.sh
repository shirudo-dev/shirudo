#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh
H=$(pwd)/helper/test-tpm-command
[ -x "$H" ] || test_skip_all "test-tpm-command helper not built"
test_expect_success 'TPM command routing separates root and Shirudo authority' '"$H"'
test_done
