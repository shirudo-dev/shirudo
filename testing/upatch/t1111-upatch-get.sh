#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1111 -- `shirudo upatch get <name>` dumps the BPF line info (source)
# of a LOADED upatch read from the kernel (the BTF the signed gen_loader
# installed). Builds + loads a marker fentry upatch, asserts `get` shows
# the marker source, then unloads + cleans up on EXIT.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-marker
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
WORK=$(mktemp -d)

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing marker fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing marker unload fixture"
"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "load failed"

test_expect_success 'upatch get dumps the loaded source line from the kernel' '
	"$SHIRUDO_BIN" upatch get "$NAME" 2>/dev/null | grep -q "shirudo_test_marker"
'

test_done
