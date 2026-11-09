#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
export SHIRUDO_BIN

test_expect_success 'staging a new BPF signer leaves this boot unchanged until canceled' '
	python3 functional/image/t5100-verity-stage.py stage "$work"
'

test_done
