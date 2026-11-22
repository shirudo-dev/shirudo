#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3115 -- the CVE-2026-31431 mitigation of upatches/kernel-cve, driven
# by the shipped reproducer: the probe reaches the algif_aead path until
# the mitigation is loaded, when an AF_ALG socket is refused, and reaches
# it again once the mitigation is unloaded.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=cve-2026-31431-af-alg-block
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
REPRO="$FIXTURES/cve-2026-31431-repro.py"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"

restore() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
}
trap restore EXIT

[ -s "$LOAD" ] || test_skip_all "missing af-alg-block fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing af-alg-block unload fixture"
[ -s "$REPRO" ] || test_skip_all "missing CVE-2026-31431 reproducer"

# The reproducer prints BROKEN, SAFE, BLOCKED or UNSUPPORTED. BLOCKED
# is the mitigation refusing the AF_ALG socket; BROKEN and SAFE are
# the exploit reaching the algif_aead decrypt without it; UNSUPPORTED is
# a kernel with no AF_ALG aead interface to attack. The CI kernel enables
# that interface (kernel-ci.conf), so a UNSUPPORTED result means this is
# not that kernel and the test cannot exercise the path it is about.
BEFORE=$(python3 "$REPRO" 2>/dev/null </dev/null)
[ "$BEFORE" != UNSUPPORTED ] || \
	test_skip_all "kernel has no AF_ALG aead interface for the reproducer"

test_expect_success 'the reproducer reaches the algif_aead path before the load' '
	[ "$BEFORE" = SAFE ] || [ "$BEFORE" = BROKEN ]
'

test_expect_success 'the mitigation loads' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN" ]
'

test_expect_success 'the reproducer is blocked while the mitigation is loaded' '
	[ "$(python3 "$REPRO" 2>/dev/null </dev/null)" = BLOCKED ]
'

test_expect_success 'a socket of another family is still created' '
	python3 -c "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close()"
'

test_expect_success 'the unload lets the reproducer reach the path again' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ] &&
	[ "$(python3 "$REPRO" 2>/dev/null </dev/null)" = "$BEFORE" ]
'

test_done
