#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
[ -x helper/test-nv-writer ] ||
	test_skip_all "test-nv-writer not built"
[ -x helper/test-tpm-preopened ] ||
	test_skip_all "test-tpm-preopened not built"
[ -x helper/test-register ] ||
	test_skip_all "test-register not built"
[ -x helper/test-nv-cphash ] ||
	test_skip_all "test-nv-cphash not built"
[ -n "${SHIRUDO_TEST_FIXTURES_DIR:-}" ] ||
	test_skip_all "target fixture directory is not set"

NAME=shirudo-test-lifecycle
LOAD="$SHIRUDO_TEST_FIXTURES_DIR/$NAME.upatch"
UNLOAD="$SHIRUDO_TEST_FIXTURES_DIR/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] ||
	test_skip_all "missing lifecycle fixtures"
[ ! -e "$PIN" ] || {
	echo "NV writer test requires an unloaded lifecycle fixture" >&2
	exit 1
}
W=$(mktemp -d) || exit 1

cleanup() {
	result=$?
	trap - EXIT
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck || result=1
	fi
	rm -f "$W/status.json" "$W/preopened.log" "$W/cphash.log" || result=1
	rmdir "$W" || result=1
	exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

writer_chain() {
	"$SHIRUDO_BIN" status --json >"$W/status.json" &&
	python3 - "$W/status.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    tpm = json.load(stream)["tpm"]
chain = tpm["chain"]
assert len(chain) == 64
assert len(bytes.fromhex(chain)) == 32
assert tpm["chain_matches_eventlog"] is True
print(chain)
PY
}

test_expect_success 'the TPM writer public key matches the init record' '
	./helper/test-nv-writer public
'

test_expect_success 'unrelated TPM signing works on both device nodes' '
	./helper/test-nv-writer sign-allowed device:/dev/tpmrm0 &&
	./helper/test-nv-writer sign-allowed device:/dev/tpm0 &&
	./helper/test-nv-writer sign-allowed-inherited device:/dev/tpmrm0
'

test_expect_success 'untrusted root cannot extend the Shirudo register' '
	./helper/test-nv-writer raw-extend /dev/tpmrm0 &&
	./helper/test-nv-writer raw-extend /dev/tpm0
'

test_expect_success 'nonblocking and inherited writes get the same denial' '
	./helper/test-nv-writer raw-extend-nonblock /dev/tpmrm0 &&
	./helper/test-nv-writer raw-extend-nonblock /dev/tpm0 &&
	./helper/test-nv-writer raw-extend-inherited /dev/tpmrm0
'

test_expect_success 'a short NV_Extend cannot bypass the guard' '
	./helper/test-nv-writer raw-extend-short /dev/tpmrm0 &&
	./helper/test-nv-writer raw-extend-short /dev/tpm0
'

test_expect_success 'an unrelated NV index passes the LSM check' '
	./helper/test-nv-writer raw-extend-other /dev/tpmrm0 &&
	./helper/test-nv-writer raw-extend-other /dev/tpm0
'

test_expect_success 'trusted loads still measure around a denied extension' '
	before=$(writer_chain) &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck &&
	[ -e "$PIN" ] &&
	loaded=$(writer_chain) &&
	[ "$loaded" != "$before" ] &&
	./helper/test-nv-writer raw-extend /dev/tpmrm0 &&
	[ "$(writer_chain)" = "$loaded" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck &&
	[ ! -e "$PIN" ] &&
	after=$(writer_chain) &&
	[ "$after" != "$loaded" ]
'

test_expect_success 'an inherited TPM connection cannot extend the register' '
	./helper/test-tpm-preopened >"$W/preopened.log" &&
	grep -qx "inherited-TPM: unsigned NV_Extend rejected by LSM; value unchanged" \
		"$W/preopened.log"
'

test_expect_success 'TPM policy binds the nonce and exact command on a scratch index' '
	before=$(writer_chain) &&
	./helper/test-nv-cphash >"$W/cphash.log" &&
	grep -qx "PolicySigned: replay and corruption rejected; value unchanged" \
		"$W/cphash.log" &&
	grep -qx "cpHash: authorized A; rejected B unchanged; extended A; scratch index removed" \
		"$W/cphash.log" &&
	[ "$(writer_chain)" = "$before" ]
'

test_expect_success 'untrusted clients can still extend an unused PCR' '
	before=$(./helper/test-register pcr 23) &&
	event=$(python3 -c "print(\"a5\" * 32)") &&
	./helper/test-register pcr-extend 23 "$event" | grep -qx "rc=0" &&
	want=$(python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex(\"$before$event\")).hexdigest())") &&
	[ "$(./helper/test-register pcr 23)" = "$want" ]
'

test_done
