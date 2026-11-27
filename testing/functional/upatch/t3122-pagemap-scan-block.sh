#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3122 -- the CVE-2026-99477 mitigations of upatches/kernel-cve, built
# from their shipped sources and driven by the shipped probe. The broad
# one refuses every PAGEMAP_SCAN with ENOTTY, the precise one only the
# scan of another process's pagemap, with EACCES; neither refuses a read
# of pagemap, and each unload lets the scans through again.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
PROBE="$FIXTURES/cve-2026-99477-pagemap-scan-probe.py"
BLOCK=cve-2026-99477-pagemap-scan-block
FOREIGN=cve-2026-99477-foreign-scan-block

pinned() {
	[ -e "/run/shirudo/bpffs/upatches/$1/link_0" ] &&
	[ -e "/run/shirudo/bpffs/upatches/$1/link_1" ]
}

load() {
	"$SHIRUDO_BIN" upatch load "$FIXTURES/$1.upatch" --no-precheck \
		>/dev/null 2>&1
}

unload() {
	"$SHIRUDO_BIN" upatch unload "$FIXTURES/$1.unload.upatch" \
		--no-precheck >/dev/null 2>&1
}

probe() {
	python3 "$PROBE" 2>/dev/null </dev/null
}

restore() {
	for name in $BLOCK $FOREIGN; do
		if [ -e "/run/shirudo/bpffs/upatches/$name" ]; then
			unload "$name" || true
		fi
		rm -f "/var/lib/shirudo/upatches/$name.upatch"
	done
}
trap restore EXIT

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -s "$PROBE" ] || test_skip_all "missing CVE-2026-99477 probe"
for name in $BLOCK $FOREIGN; do
	[ -s "$FIXTURES/$name.upatch" ] || test_skip_all "missing $name fixture"
	[ -s "$FIXTURES/$name.unload.upatch" ] ||
		test_skip_all "missing $name unload fixture"
done

BEFORE=$(probe)
case "$BEFORE" in
ENOTTY\ *|EINVAL\ *) test_skip_all "kernel has no PAGEMAP_SCAN" ;;
esac

test_expect_success 'a scan of its own pagemap and of a child runs before a load' '
	[ "$BEFORE" = "ok ok ok" ]
'

test_expect_success 'the broad mitigation loads' '
	load $BLOCK &&
	pinned $BLOCK
'

test_expect_success 'every scan fails with ENOTTY, a read of pagemap does not' '
	[ "$(probe)" = "ENOTTY ENOTTY ok" ]
'

test_expect_success 'its unload lets the scans through again' '
	unload $BLOCK &&
	! pinned $BLOCK &&
	[ "$(probe)" = "ok ok ok" ]
'

test_expect_success 'the precise mitigation loads' '
	load $FOREIGN &&
	pinned $FOREIGN
'

test_expect_success 'the scan of another process fails with EACCES, its own does not' '
	[ "$(probe)" = "ok EACCES ok" ]
'

test_expect_success 'its unload lets the scan through again' '
	unload $FOREIGN &&
	! pinned $FOREIGN &&
	[ "$(probe)" = "ok ok ok" ]
'

test_done
