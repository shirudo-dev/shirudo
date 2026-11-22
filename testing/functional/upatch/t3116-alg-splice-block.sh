#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3116 -- the precise CVE-2026-31431 mitigation of upatches/kernel-cve.
# It refuses a zero-copy splice into an AF_ALG socket, the vulnerability's
# precondition, while leaving the copying sendmsg path working. The probe
# issues a copying sendmsg before the splice, so SPLICE_BLOCKED proves the
# copy was allowed and only the splice refused.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=cve-2026-31431-alg-splice-block
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PROBE="$FIXTURES/cve-2026-31431-splice-probe.py"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing alg-splice-block fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing alg-splice-block unload fixture"
[ -s "$PROBE" ] || test_skip_all "missing CVE-2026-31431 splice probe"

BEFORE=$(python3 "$PROBE" 2>/dev/null </dev/null)
[ "$BEFORE" != UNSUPPORTED ] || \
	test_skip_all "kernel has no AF_ALG aead interface for the probe"

test_expect_success 'a zero-copy splice into AF_ALG is allowed before the load' '
	[ "$BEFORE" = SPLICE_OK ]
'

test_expect_success 'the mitigation loads' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN" ]
'

test_expect_success 'the splice is refused but the copying sendmsg is allowed' '
	[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = SPLICE_BLOCKED ]
'

test_expect_success 'a socket of another family is unaffected' '
	python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()"
'

test_expect_success 'the unload lets the splice through again' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ] &&
	[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = SPLICE_OK ]
'

test_done
