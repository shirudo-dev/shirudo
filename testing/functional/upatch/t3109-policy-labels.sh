#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3109 -- a signed policy section labels executables and ordinary files,
# ORing multiple declarations with an existing file xattr, and a pattern
# labels the regular files of its directory that it matches.

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
printf '#!/bin/sh\n/bin/true\n' >"$WORK/executable"
printf '#!/bin/sh\npython3 -c '\''import socket; s=socket.socket();\ntry: s.connect(("127.0.0.1", 9))\nexcept PermissionError: raise SystemExit(0)\nexcept OSError: raise SystemExit(1)\nraise SystemExit(2)'\''\n' \
	>"$WORK/socket-executable"
printf 'ordinary file\n' >"$WORK/ordinary"
chmod 0755 "$WORK/executable" "$WORK/socket-executable"
"$PROBE" set-policy "$WORK/ordinary" 0x8 ||
	test_skip_all "scratch filesystem cannot store policy xattrs"
# What the fixture's pattern, match-*, meets in its directory.
printf 'first\n' >"$WORK/match-a"
printf 'second\n' >"$WORK/match-b"
printf 'other\n' >"$WORK/unmatched"
mkdir "$WORK/match-dir"
ln -s ordinary "$WORK/match-link"
"$PROBE" set-policy "$WORK/match-b" 0x40 ||
	test_skip_all "scratch filesystem cannot store policy xattrs"

test_expect_success 'policy section binds task and socket maps and labels files' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck &&
	{ ! "$WORK/executable" >/dev/null 2>&1 || {
		echo "policy executable was allowed" >&2; false;
	}; } &&
	{ "$WORK/socket-executable" >/dev/null 2>&1 || {
		echo "socket policy executable failed" >&2; false;
	}; } &&
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

# The symbolic link names a file the pattern does not: its target keeps
# the bits of the test above.
test_expect_success 'a pattern labels the regular files it matches and nothing else' '
	python3 - "$WORK" <<'"'"'PY'"'"'
import errno
import os
import sys

def policy(name):
    try:
        value = os.getxattr(os.path.join(sys.argv[1], name),
                            "security.bpf.shirudo.policy")
    except OSError as error:
        assert error.errno == errno.ENODATA, (name, error)
        return None
    assert len(value) == 8, (name, len(value))
    return int.from_bytes(value, byteorder=sys.byteorder)

assert policy("match-a") == 0x20
assert policy("match-b") == 0x60
assert policy("unmatched") is None
assert policy("match-dir") is None
assert policy("ordinary") == 0xe
PY
'

test_done
