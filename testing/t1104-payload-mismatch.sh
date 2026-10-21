#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1104 -- unload payload_mismatch: a signed UNLOAD directive whose
# expected payload_sha256 does not match the loaded upatch's pin xattr
# is refused with category payload_mismatch and detaches nothing. The
# directive's signature still verifies (operator key); only the payload
# binding is wrong. Non-destructive: the pin survives.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
UP=shirudo-test-basic
UNLOAD="$FIXTURES/shirudo-test-basic-mismatch.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$UP/link"
[ -e "$PIN" ] || test_skip_all "basic fixture is not loaded"
[ -s "$UNLOAD" ] || test_skip_all "missing prebuilt mismatch unload fixture"

test_expect_success 'wrong expected payload -> payload_mismatch, pin intact' '
	cat=$($SHIRUDO_BIN upatch unload "$UNLOAD" --no-precheck \
	      --report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "payload_mismatch" ] &&
	[ -e "$PIN" ]
'

# Rewrites a .upatch: flags |= <flag>, metadata replaced by <hex> (32
# bytes, appended), the signed loader and data untouched.
forge() {
	python3 - "$1" "$2" "$3" "$4" <<'PY'
import struct, sys
src, dst, flag, meta = sys.argv[1], sys.argv[2], int(sys.argv[3]), bytes.fromhex(sys.argv[4])
b = bytearray(open(src, 'rb').read())
struct.pack_into('<I', b, 12, struct.unpack_from('<I', b, 12)[0] | flag)
struct.pack_into('<II', b, 8 + 4 + 4 + 256 + 32 + 16, len(b), len(meta))
open(dst, 'wb').write(bytes(b) + meta)
PY
}

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

test_expect_success 'a directive repointed at another payload is refused' '
	forge "$FIXTURES/shirudo-test-basic.unload.upatch" "$T/edited.upatch" \
		0 "$(printf "bb%.0s" $(seq 32))" &&
	cat=$($SHIRUDO_BIN upatch unload "$T/edited.upatch" --no-precheck \
	      --report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "parser_rejected" ] &&
	[ -e "$PIN" ]
'

test_expect_success 'a LOAD artifact flagged as a directive unloads nothing' '
	payload=$($SHIRUDO_BIN upatch info "$FIXTURES/shirudo-test-basic.upatch" \
		  --json | python3 -c "import json,sys; print(json.load(sys.stdin)[\"payload_sha256\"])") &&
	forge "$FIXTURES/shirudo-test-basic.upatch" "$T/flagged.upatch" 1 \
		"$payload" &&
	cat=$($SHIRUDO_BIN upatch unload "$T/flagged.upatch" --no-precheck \
	      --report=- 2>/dev/null | report_field category) &&
	[ "$cat" = "parser_rejected" ] &&
	[ -e "$PIN" ]
'

test_done
