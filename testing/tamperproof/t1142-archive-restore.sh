#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1142 -- an artifact renamed into the archive after the register was
# bound. Rename brings an inode into a sealed directory without creating
# one, so root can place any operator-signed .upatch there; a re-run of
# init used to restore it, attached and pinned, without a register event,
# since this boot's init event was already on record. init must now
# refuse the restore and leave the artifact unloaded. Cleaned up through
# the artifact's own unload directive, which removes the archive copy.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-scope-kprobe
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
ARCHIVE=/var/lib/shirudo/upatches
STAGE=/var/lib/t1142-stage
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing scope fixtures"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"

restore() {
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true
	rm -rf "$STAGE"
	"$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

CHAIN=$("$SHIRUDO_BIN" status --json 2>/dev/null |
	python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])")

test_expect_success 'root can rename a signed artifact into the archive' '
	mkdir -p "$STAGE" && cp "$LOAD" "$STAGE/$NAME.upatch" &&
	mv "$STAGE/$NAME.upatch" "$ARCHIVE/$NAME.upatch" &&
	[ -e "$ARCHIVE/$NAME.upatch" ]
'

test_expect_success 'a re-run of init refuses to restore it unmeasured' '
	! "$SHIRUDO_BIN" init >/dev/null 2>"$STAGE/init.err" &&
	grep -q "archived but not loaded after the register was bound" \
		"$STAGE/init.err" &&
	[ ! -e "$PIN" ] &&
	[ "$("$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])")" = "$CHAIN" ]
'

test_expect_success 'the unload directive removes the planted copy and init completes again' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck --report=- 2>/dev/null |
		report_field category | grep -qx already_unloaded &&
	[ ! -e "$ARCHIVE/$NAME.upatch" ] &&
	"$SHIRUDO_BIN" init >/dev/null 2>&1 &&
	[ "$("$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])")" = "$CHAIN" ]
'

test_done
