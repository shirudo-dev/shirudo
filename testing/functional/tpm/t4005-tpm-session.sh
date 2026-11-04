#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

[ -x helper/tpmsim-cmd ] || test_skip_all "tpmsim-cmd not built (libtpms required)"
WORK=$(mktemp -d) || exit 1
cleanup() {
	for mode in unsalted-control nv-extend nv-replay pcr-extend nv-read \
		    pcr-read clock policy-digest identity; do
		rm -f "$WORK/$mode/permanent" "$WORK/$mode/volatile" "$WORK/$mode/NVChip"
		rmdir "$WORK/$mode"
	done
	rmdir "$WORK"
}
trap cleanup EXIT

for mode in unsalted-control nv-extend nv-replay pcr-extend nv-read \
	    pcr-read clock policy-digest identity; do
	export SHIRUDO_TPM_TCTI="cmd:$(pwd)/helper/tpmsim-cmd $WORK/$mode"
	test_expect_success "TPM session: $mode" '
		./helper/test-tpm-session "$mode"
	'
done

test_done
