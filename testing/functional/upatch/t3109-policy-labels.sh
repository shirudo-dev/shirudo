#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3109 -- a signed policy section labels executables and ordinary files,
# ORing multiple declarations with an existing file xattr.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
LOAD="$FIXTURES/shirudo-test-policy-labels.upatch"
UNLOAD="$FIXTURES/shirudo-test-policy-labels.unload.upatch"
PROBE=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
WORK=/tmp/shirudo-policy-label-test
PIN=/run/shirudo/bpffs/upatches/policy-labels/link

restore()
{
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap restore EXIT HUP INT TERM

[ -s "$LOAD" ] || test_skip_all "missing policy-label fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing policy-label unload fixture"
[ -x "$PROBE" ] || test_skip_all "runtime policy probe is missing"
rm -rf "$WORK"
mkdir -p "$WORK"
printf '#!/bin/sh\nexit 0\n' >"$WORK/executable"
printf 'ordinary file\n' >"$WORK/ordinary"
chmod 0755 "$WORK/executable"
"$PROBE" set-policy "$WORK/ordinary" 0x8 ||
	test_skip_all "scratch filesystem cannot store policy xattrs"

test_expect_success 'upatch labels executable and ordinary files without clearing existing bits' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	python3 - "$WORK/executable" "$WORK/ordinary" <<'"'"'PY'"'"'
import os
import sys

def policy(path):
    value = os.getxattr(path, "security.bpf.shirudo.policy")
    assert len(value) == 8, (path, len(value))
    return int.from_bytes(value, byteorder=sys.byteorder)

assert policy(sys.argv[1]) == 0x1
assert policy(sys.argv[2]) == 0xe
PY
'

test_done
