#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1132 -- target-side artifact signature, pin-xattr and link protection.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=$SHIRUDO_TEST_FIXTURES_DIR
NAME=shirudo-test-basic
LOAD="$FIXTURES/$NAME.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
PINDIR="/run/shirudo/bpffs/upatches/$NAME"
ARCHIVE="/var/lib/shirudo/upatches/$NAME.upatch"
HELPER=helper/test-upatch-link-lockdown
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
[ -s "$LOAD" ] || test_skip_all "missing trusted basic upatch"
[ -x "$HELPER" ] || test_skip_all "upatch link helper is not built"
[ -e "$PIN" ] || test_skip_all "basic fixture is not loaded"
[ -s "$ARCHIVE" ] || test_skip_all "basic fixture archive is missing"
python3 - "$LOAD" "$WORK/mutated.upatch" <<'PY'
import hashlib, pathlib, struct, sys
src, dst = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
data = bytearray(src.read_bytes())
loader_off, loader_len = struct.unpack_from("<II", data, 304)
data_off, data_len = struct.unpack_from("<II", data, 328)
name = b"shirudo-tamper-invalid-signature"
data[16:272] = name + bytes(256 - len(name))
data[loader_off] ^= 1
payload = data[loader_off:loader_off + loader_len]
if data_len:
    payload += data[data_off:data_off + data_len]
data[272:304] = hashlib.sha256(payload).digest()
dst.write_bytes(data)
PY
test_expect_success 'trusted certificate cannot authorize a mutated loader' '
	"$SHIRUDO_BIN" upatch load "$WORK/mutated.upatch" --no-precheck \
		--report="$WORK/report.json" >/dev/null 2>&1 || true
	cat=$(report_field category <"$WORK/report.json") &&
	[ "$cat" = signature_rejected ] &&
	[ ! -e /run/shirudo/bpffs/upatches/shirudo-tamper-invalid-signature ] &&
	[ ! -e /var/lib/shirudo/upatches/shirudo-tamper-invalid-signature.upatch ]
'
test_expect_success 'root cannot change the live payload binding xattr' '
	before=$(python3 -c "import os,sys; print(os.getxattr(sys.argv[1], \"security.bpf.shirudo.payload\").hex())" "$PINDIR") &&
	! python3 -c "import os,sys; os.setxattr(sys.argv[1], \"security.bpf.shirudo.payload\", bytes(32))" "$PINDIR" 2>/dev/null &&
	! python3 -c "import os,sys; os.removexattr(sys.argv[1], \"security.bpf.shirudo.payload\")" "$PINDIR" 2>/dev/null &&
	after=$(python3 -c "import os,sys; print(os.getxattr(sys.argv[1], \"security.bpf.shirudo.payload\").hex())" "$PINDIR") &&
	[ "$before" = "$after" ]
'
test_expect_success 'root cannot detach or update a live upatch link' '
	"$HELPER" "$PIN" &&
	[ -e "$PIN" ]
'
test_done
