#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3111 -- a upatch whose fentry program attaches to the program of another
# upatch loads only on top of exactly the build it was made against.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
TARGET=shirudo-test-bpf-target
FENTRY=shirudo-test-bpf-fentry
BPFFS=/run/shirudo/bpffs/upatches
WORK=$(mktemp -d)

unload_if_pinned() {
	if [ -e "$BPFFS/$1/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$2.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$1.upatch" 2>/dev/null || :
}

restore() {
	unload_if_pinned "$FENTRY" "$FENTRY"
	unload_if_pinned "$TARGET" "$TARGET"
	unload_if_pinned "$TARGET" "$TARGET-variant"
	rm -rf "$WORK"
}
trap restore EXIT

hits() {
	"$SHIRUDO_BIN" upatch map "$FENTRY" bpf_fentry_hits |
		awk '$1 == "->" { print $2; found = 1 } END { exit !found }'
}

for f in "$TARGET" "$TARGET-variant" "$FENTRY"; do
	[ -s "$FIXTURES/$f.upatch" ] || test_skip_all "missing $f fixture"
	[ -s "$FIXTURES/$f.unload.upatch" ] || test_skip_all "missing $f unload fixture"
done
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

test_expect_success 'without its target the upatch is refused before its loader runs' '
	! "$SHIRUDO_BIN" upatch load "$FIXTURES/$FENTRY.upatch" --no-precheck \
		--report="$WORK/missing.json" >/dev/null 2>&1 &&
	[ "$(report_field category <"$WORK/missing.json")" = attach_target_missing ] &&
	[ ! -e "$BPFFS/$FENTRY" ]
'

test_expect_success 'the target pins its program for other upatches' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$TARGET.upatch" --no-precheck \
		>/dev/null 2>&1 &&
	[ -e "$BPFFS/$TARGET/progs/prog_0" ]
'

test_expect_success 'on top of its target the upatch loads and runs with it' '
	{ "$SHIRUDO_BIN" upatch load "$FIXTURES/$FENTRY.upatch" --no-precheck \
		--report="$WORK/load.json" >/dev/null 2>&1 ||
	  { cat "$WORK/load.json" >&2; false; }; } &&
	[ -e "$BPFFS/$FENTRY/link" ] &&
	before=$(hits) &&
	sleep 0.1 && sleep 0.1 &&
	after=$(hits) &&
	[ "$after" -gt "$before" ]
'

test_expect_success 'unloading both removes their pins' '
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$FENTRY.unload.upatch" \
		--no-precheck >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$TARGET.unload.upatch" \
		--no-precheck >/dev/null 2>&1 &&
	[ ! -e "$BPFFS/$FENTRY" ] && [ ! -e "$BPFFS/$TARGET" ]
'

test_expect_success 'on top of another build of its target the upatch is refused' '
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$TARGET-variant.upatch" \
		--no-precheck >/dev/null 2>&1 &&
	! "$SHIRUDO_BIN" upatch load "$FIXTURES/$FENTRY.upatch" --no-precheck \
		--report="$WORK/mismatch.json" >/dev/null 2>&1 &&
	[ "$(report_field category <"$WORK/mismatch.json")" = payload_mismatch ] &&
	[ ! -e "$BPFFS/$FENTRY" ]
'

test_done
