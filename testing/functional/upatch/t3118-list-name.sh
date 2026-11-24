#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3118 -- `upatch list` prints the header names of the archive's files
# as they are on disk, signature unchecked, so a stray byte or a control
# character in one is as hostile as the file `upatch info` is handed. A
# row has to show "?" for what a terminal would eat and the --json
# member degrades to U+FFFD, the way `upatch info` already reports it.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

ARCHIVE=/var/lib/shirudo/upatches
SIGNED=$ARCHIVE/t3118-cname.upatch
UNREADABLE=$ARCHIVE/t3118-bad$(printf '\033')[2Jname.upatch
WORK=$(mktemp -d)

cleanup() {
	rm -f "$SIGNED" "$UNREADABLE"
	rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$ARCHIVE"

# A valid container whose header name carries a control byte, a UTF-8
# control and a stray byte: the name any .upatch can bring along.
python3 - <<'PY'
import struct
header = bytearray(369)
struct.pack_into("<QII", header, 0, 0x53485244554E4150, 1, 0)
header[16:32] = b"a\x1b[2Jb\xc2\x9bc\xff".ljust(16, bytes([0]))
struct.pack_into("<14I", header, 304, 360, 8, 368, 1, 0, 0, 0, 0,
                 4096, 0, 0, 0, 1, 0)
header[360:368] = b"12345678"
header[368] = 0x41
open("/var/lib/shirudo/upatches/t3118-cname.upatch", "wb").write(header)
PY

# An unparseable entry whose filename itself carries a control.
head -c 64 /dev/urandom > "$UNREADABLE"

test_expect_success 'a name with controls shows its controls as ?' '
	"$SHIRUDO_BIN" upatch list >"$WORK/list" 2>/dev/null &&
	grep -q "a?\[2Jb??c?" "$WORK/list" &&
	! grep -q "$(printf "\033")" "$WORK/list"
'

test_expect_success 'upatch list --json writes a stray byte of a name as U+FFFD' '
	"$SHIRUDO_BIN" upatch list --json >"$WORK/list.json" &&
	python3 - "$WORK/list.json" <<"PY"
import json, sys
names = [u["name"] for u in json.load(open(sys.argv[1]))["upatches"]]
assert "a\x1b[2Jb\x9bc\ufffd" in names, names
PY
'

test_expect_success 'an unreadable entry shows its filename sanitized' '
	"$SHIRUDO_BIN" upatch list >"$WORK/list" 2>/dev/null &&
	grep -q "t3118-bad?\[2Jname.upatch" "$WORK/list" &&
	! grep -q "$(printf "\033")" "$WORK/list"
'

test_done
