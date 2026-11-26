#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3001 -- the .upatch container parser is the target's trust boundary:
# an attacker can hand it an arbitrary file. It must reject malformed
# input cleanly (non-zero exit, never a crash). Driven through the real
# core binary's read-only `upatch info`, and through a load it refuses
# before it reaches the kernel; needs no root, kernel, or clang.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/empty"
head -c 8 /dev/urandom > "$WORK/trunc"
head -c 65536 /dev/urandom > "$WORK/garbage"
printf 'SHIRUDO\0not-a-real-header-just-magic-ish' > "$WORK/badmagic"

# Rejected cleanly == non-zero exit and not killed by a signal (>=128,
# e.g. 139 = SIGSEGV). A clean parser error is the only acceptable
# outcome for any of these inputs.
reject() {
	"$S" upatch info "$1" >/dev/null 2>&1
	rc=$?
	[ "$rc" -ne 0 ] && [ "$rc" -lt 128 ]
}

test_expect_success 'empty file rejected, no crash' '
	reject "$WORK/empty"
'

test_expect_success 'truncated file (8 bytes) rejected, no crash' '
	reject "$WORK/trunc"
'

test_expect_success 'random garbage rejected, no crash' '
	reject "$WORK/garbage"
'

test_expect_success 'plausible-magic-but-bogus rejected, no crash' '
	reject "$WORK/badmagic"
'

test_expect_success 'nonexistent file rejected, no crash' '
	reject "$WORK/does-not-exist"
'

test_expect_success 'a directory path rejected, no crash' '
	reject "$WORK"
'

python3 - "$WORK" <<'PY'
import pathlib, struct, sys
root = pathlib.Path(sys.argv[1])
header = bytearray(369)
struct.pack_into("<QII", header, 0, 0x53485244554E4150, 1, 0)
header[16:32] = b"structured-test".ljust(16, bytes([0]))
struct.pack_into("<14I", header, 304, 360, 8, 368, 1, 0, 0, 0, 0,
                 4096, 0, 0, 0, 1, 0)
header[360:368] = b"12345678"
header[368] = 0x41
(root / "valid-structured").write_bytes(header)
def mutate(name, off, fmt, value):
    data = bytearray(header)
    struct.pack_into(fmt, data, off, value)
    (root / name).write_bytes(data)
mutate("bad-version", 8, "<I", 2)
mutate("rodata-offset-oob", 348, "<I", 1)
mutate("reserved1", 356, "<I", 1)
mutate("zero-loader", 308, "<I", 0)
mutate("zero-signature", 316, "<I", 0)
mutate("loader-in-header", 304, "<I", 359)
mutate("signature-oob", 312, "<I", 0xfffffff0)
mutate("data-overflow", 328, "<I", 0xfffffff0)
mutate("reserved2", 320, "<I", 368)
mutate("reserved3", 324, "<I", 1)
mutate("data-len-overflow", 332, "<I", 0xffffffff)
data = bytearray(header)
data[16:32] = b"a\x1b[2Jb\xc2\x9bc\xff".ljust(16, bytes([0]))
(root / "controls-in-name").write_bytes(data)
with (root / "oversized").open("wb") as f:
    f.truncate(16 * 1024 * 1024 + 1)
PY
test_expect_success 'structured valid container parses' '
	"$S" upatch info "$WORK/valid-structured" >/dev/null 2>&1
'
test_expect_success 'structured header and section bounds fail cleanly' '
	for f in bad-version rodata-offset-oob reserved1 reserved2 reserved3 \
		 zero-loader zero-signature loader-in-header signature-oob \
		 data-overflow data-len-overflow; do reject "$WORK/$f" || exit 1; done
'
test_expect_success 'a name from the file shows its controls as ?' '
	"$S" upatch info "$WORK/controls-in-name" >"$WORK/info.out" 2>&1 &&
	grep -q "^Name: *a?\[2Jb??c?\$" "$WORK/info.out" &&
	! grep -q "$(printf "\033")" "$WORK/info.out"
'
test_expect_success 'upatch info --json writes a stray byte of a name as U+FFFD' '
	"$S" upatch info --json "$WORK/controls-in-name" >"$WORK/info.json" &&
	python3 - "$WORK/info.json" <<"PY"
import json, sys
name = json.load(open(sys.argv[1]))["name"]
assert name == "a\x1b[2Jb\x9bc\ufffd", repr(name)
PY
'
test_expect_success 'a refused load reports a name that is no UTF-8' '
	! "$S" upatch load --no-precheck --report=- "$WORK/controls-in-name" \
		>"$WORK/report.json" 2>"$WORK/report.err" &&
	python3 - "$WORK/report.json" <<"PY"
import json, sys
report = json.load(open(sys.argv[1]))
assert report["category"] == "parser_rejected", report
assert report["upatch"]["name"] == "a\x1b[2Jb\x9bc\ufffd", report
PY
'
test_expect_success 'upatch info --json grows to hold a long escaped path' '
	dir=$WORK && seg=$(printf "\001%.0s" $(seq 200)) &&
	for i in $(seq 15); do dir=$dir/$seg; done &&
	mkdir -p "$dir" && cp "$WORK/valid-structured" "$dir/u" &&
	"$S" upatch info --json "$dir/u" >"$WORK/long.json" &&
	[ "$(wc -c <"$WORK/long.json")" -gt 16384 ]
'
test_expect_success 'file larger than 16 MiB is rejected without mapping it' '
	reject "$WORK/oversized"
'
test_done
