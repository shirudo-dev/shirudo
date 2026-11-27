#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3121 -- the CVE-2026-98432 mitigation of upatches/kernel-cve, driven
# by the shipped probe: a user task creates an MPTCP socket until the
# mitigation is loaded, is refused while it is, and creates one again
# once the mitigation is unloaded. Plain TCP is never refused.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=cve-2026-98432-mptcp-block
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PROBE="$FIXTURES/cve-2026-98432-mptcp-probe.py"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing mptcp-block fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing mptcp-block unload fixture"
[ -s "$PROBE" ] || test_skip_all "missing CVE-2026-98432 probe"

# The probe prints OPEN, BLOCKED or UNSUPPORTED. The CI kernel enables
# MPTCP (kernel-ci.conf), so UNSUPPORTED means this is not that kernel.
# The hook runs before the protocol lookup, so on a kernel without MPTCP
# a loaded shield would still answer BLOCKED and prove nothing.
BEFORE=$(python3 "$PROBE" 2>/dev/null </dev/null)
[ "$BEFORE" != UNSUPPORTED ] || \
	test_skip_all "kernel has no MPTCP for the probe"

test_expect_success 'a user task creates an MPTCP socket before the load' '
	[ "$BEFORE" = OPEN ]
'

test_expect_success 'the mitigation loads' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN" ]
'

test_expect_success 'an MPTCP socket is refused while the mitigation is loaded' '
	[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = BLOCKED ]
'

test_expect_success 'a plain TCP socket is still created' '
	python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP).close()"
'

test_expect_success 'the unload lets a user task create an MPTCP socket again' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ] &&
	[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = OPEN ]
'

test_done
