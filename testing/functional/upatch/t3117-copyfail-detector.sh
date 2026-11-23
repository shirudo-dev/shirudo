#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t3117 -- the CVE-2026-31431 copy-failure detector of upatches/kernel-cve.
# socket_sendmsg marks an AF_ALG socket whose send carried a zero-copy
# splice; aead_recvmsg counts every op as the activity denominator and, for
# a marked socket whose op failed, a hit: the foreign-page writeback. A
# spliced failing decrypt moves hits; an ordinary copying failing decrypt
# moves only activity, so the detector separates the two.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=cve-2026-31431-copyfail-detector
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PROBE="$FIXTURES/cve-2026-31431-splice-probe.py"
PIN=/run/shirudo/bpffs/upatches/$NAME/link_0
PIN1=/run/shirudo/bpffs/upatches/$NAME/link_1
WORK=$(mktemp -d)

cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

[ -s "$LOAD" ] || test_skip_all "missing copyfail-detector fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing copyfail-detector unload fixture"
[ -s "$PROBE" ] || test_skip_all "missing CVE-2026-31431 splice probe"

# The probe reaches a zero-copy splice into an AF_ALG aead socket only
# where the kernel offers that path; without it there is nothing to count.
[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = SPLICE_OK ] ||
	test_skip_all "kernel has no AF_ALG aead splice path to exercise"

# Drive one failing aead decrypt, its ciphertext delivered either by a
# zero-copy splice (foreign pages, the detector's hit) or by an ordinary
# copying send (the activity denominator only).
cat >"$WORK/drive.py" <<'PY'
import os
import socket
import struct
import sys

AF_ALG = getattr(socket, "AF_ALG", 38)
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5
ALG_OP_DECRYPT = 0


def authenc_key(authkey, enckey):
    # struct crypto_authenc_key_param in an rtattr, then the two keys.
    param = struct.pack(">I", len(enckey))
    rta_len = 4 + len(param)
    rtattr = struct.pack("HH", rta_len, 1) + param
    rtattr += b"\x00" * ((-rta_len) % 4)
    return rtattr + authkey + enckey


try:
    with open("/proc/sys/crypto/af_alg_restrict", "w") as f:
        f.write("0")
except OSError:
    pass

try:
    alg = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
except OSError:
    print("UNSUPPORTED")
    sys.exit(0)
with alg:
    try:
        alg.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 16)
        alg.setsockopt(SOL_ALG, ALG_SET_KEY,
                       authenc_key(b"\x00" * 32, b"\x00" * 16))
        op, _ = alg.accept()
    except OSError:
        print("UNSUPPORTED")
        sys.exit(0)
    with op:
        aad = b"\x00" * 16
        try:
            op.sendmsg(
                [aad],
                [(SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
                 (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
                 (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", len(aad)))],
                socket.MSG_MORE,
            )
        except OSError:
            print("UNSUPPORTED")
            sys.exit(0)
        if sys.argv[1] == "splice":
            r_pipe, w_pipe = os.pipe()
            try:
                os.write(w_pipe, b"\x00" * 32)
                try:
                    os.splice(r_pipe, op.fileno(), 32)
                except (OSError, AttributeError):
                    print("UNSUPPORTED")
                    sys.exit(0)
            finally:
                os.close(r_pipe)
                os.close(w_pipe)
        else:
            try:
                op.sendmsg([b"\x00" * 32])
            except OSError:
                print("UNSUPPORTED")
                sys.exit(0)
        try:
            op.recv(4096)
        except OSError:
            pass
        print("OK")
PY

# The per-cpu counters are summed across CPUs under "sum" in the map JSON.
read_count() {
	"$SHIRUDO_BIN" upatch get "$NAME" --json |
		python3 -c 'import json, sys
doc = json.load(sys.stdin)
m = next(x for x in doc["upatch"]["maps"] if x["name"] == sys.argv[1])
print(int(m["entries"][0]["sum"], 0))' "$1"
}

test_expect_success 'the detector loads with both of its programs pinned' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN" ] &&
	[ -e "$PIN1" ]
'

test_expect_success 'a spliced failing decrypt moves hits and activity' '
	hits_before=$(read_count hits) &&
	activity_before=$(read_count activity) &&
	[ "$(python3 "$WORK/drive.py" splice)" = OK ] &&
	hits_after=$(read_count hits) &&
	activity_after=$(read_count activity) &&
	[ "$hits_after" -gt "$hits_before" ] &&
	[ "$activity_after" -gt "$activity_before" ]
'

test_expect_success 'an ordinary copying failing decrypt moves only activity' '
	hits_before=$(read_count hits) &&
	activity_before=$(read_count activity) &&
	[ "$(python3 "$WORK/drive.py" copy)" = OK ] &&
	hits_after=$(read_count hits) &&
	activity_after=$(read_count activity) &&
	[ "$hits_after" = "$hits_before" ] &&
	[ "$activity_after" -gt "$activity_before" ]
'

test_expect_success 'the detector unloads' '
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

test_done
