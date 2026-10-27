#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1141 -- a path root names for shirudo to write. The seal lets the
# runtime task write what it denies everyone else, so a --report, --out
# or --json path pointed at sealed state, directly or through a symbolic
# link, must be refused rather than clobber the eventlog or plant a file
# the next boot restores. Non-destructive: every refusal leaves the state
# as it was.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

EVENTLOG=/var/lib/shirudo/eventlog
ARCHIVE=/var/lib/shirudo/upatches
PLANTED="$ARCHIVE/t1141-planted.upatch"
LINK=/tmp/t1141-eventlog.link
[ -s "$EVENTLOG" ] || test_skip_all "no eventlog at $EVENTLOG"

restore() {
	rm -f "$LINK"
}
trap restore EXIT

BEFORE=$(sha256sum "$EVENTLOG" | cut -d" " -f1)

test_expect_success 'a load report is not written over the eventlog' '
	! "$SHIRUDO_BIN" upatch load /nonexistent.upatch --no-precheck \
		--report="$EVENTLOG" >/dev/null 2>"$LINK.err" &&
	grep -q "refusing to write sealed state" "$LINK.err" &&
	[ "$(sha256sum "$EVENTLOG" | cut -d" " -f1)" = "$BEFORE" ]
'

test_expect_success 'a load report is not written through a link to the eventlog' '
	ln -sf "$EVENTLOG" "$LINK" &&
	! "$SHIRUDO_BIN" upatch load /nonexistent.upatch --no-precheck \
		--report="$LINK" >/dev/null 2>"$LINK.err" &&
	grep -q "symbolic links" "$LINK.err" &&
	[ "$(sha256sum "$EVENTLOG" | cut -d" " -f1)" = "$BEFORE" ]
'

test_expect_success 'a load report does not plant a file in the archive' '
	! "$SHIRUDO_BIN" upatch load /nonexistent.upatch --no-precheck \
		--report="$PLANTED" >/dev/null 2>"$LINK.err" &&
	grep -q "refusing to write sealed state" "$LINK.err" &&
	[ ! -e "$PLANTED" ]
'

test_expect_success 'a map listing is not appended to the eventlog' '
	! "$SHIRUDO_BIN" upatch map --json="$EVENTLOG" >/dev/null 2>&1 &&
	[ "$(sha256sum "$EVENTLOG" | cut -d" " -f1)" = "$BEFORE" ]
'

test_expect_success 'evidence is not written over the eventlog' '
	! "$SHIRUDO_BIN" attest --nonce=00 --out="$EVENTLOG" \
		>/dev/null 2>"$LINK.err" &&
	grep -q "refusing to write sealed state" "$LINK.err" &&
	[ "$(sha256sum "$EVENTLOG" | cut -d" " -f1)" = "$BEFORE" ]
'

test_expect_success 'the eventlog still replays' '
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d[\"tpm\"][\"chain_matches_eventlog\"] else 1)"
'

test_done
