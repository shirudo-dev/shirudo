#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0004 -- the .upatch container parser is the target's trust boundary:
# an attacker can hand it an arbitrary file. It must reject malformed
# input cleanly (non-zero exit, never a crash). Driven through the real
# core binary's read-only `upatch info`; needs no root, kernel, or clang.

cd "$(dirname "$0")/.."
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
data = bytearray(header)
struct.pack_into("<II", data, 320, 359, 1)
(root / "metadata-in-header").write_bytes(data)
mutate("data-len-overflow", 332, "<I", 0xffffffff)
with (root / "oversized").open("wb") as f:
    f.truncate(16 * 1024 * 1024 + 1)
PY
test_expect_success 'structured valid container parses' '
	"$S" upatch info "$WORK/valid-structured" >/dev/null 2>&1
'
test_expect_success 'structured header and section bounds fail cleanly' '
	for f in bad-version rodata-offset-oob reserved1 zero-loader zero-signature \
		 loader-in-header signature-oob data-overflow metadata-in-header \
		 data-len-overflow; do reject "$WORK/$f" || exit 1; done
'
test_expect_success 'file larger than 16 MiB is rejected without mapping it' '
	reject "$WORK/oversized"
'
test_done
