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
[ -x helper/test-nv-cphash ] ||
	test_skip_all "test-nv-cphash not built"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] ||
	test_skip_all "missing lifecycle fixtures"
[ ! -e "$PIN" ] || {
	echo "NV writer test requires an unloaded lifecycle fixture" >&2
	exit 1
}
W=$(mktemp -d)

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
import json, sys
tpm = json.load(open(sys.argv[1]))["tpm"]
chain = tpm["chain"]
assert len(chain) == 64
assert len(bytes.fromhex(chain)) == 32
assert tpm["chain_matches_eventlog"] is True
print(chain)
PY
}

test_expect_success 'the writer public area is available in the init record' '
	./helper/test-nv-writer public
'

test_expect_success 'root cannot read the kernel-held private writer key' '
	./helper/test-nv-writer private-read
'

test_expect_success 'root cannot sign while the trusted NV writer remains live' '
	before=$(writer_chain) &&
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck &&
	[ -e "$PIN" ] &&
	loaded=$(writer_chain) &&
	[ "$loaded" != "$before" ] &&
	./helper/test-nv-writer sign &&
	./helper/test-nv-writer sign-shared &&
	[ "$(writer_chain)" = "$loaded" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck &&
	[ ! -e "$PIN" ] &&
	after=$(writer_chain) &&
	[ "$after" != "$loaded" ]
'

test_expect_success 'root cannot update, revoke or invalidate the NV signing key' '
	./helper/test-nv-writer update &&
	./helper/test-nv-writer revoke &&
	./helper/test-nv-writer invalidate
'

test_expect_success 'root cannot change the NV signing key permissions' '
	./helper/test-nv-writer setperm
'

test_expect_success 'root cannot clear, revoke, invalidate or change the writer keyring' '
	./helper/test-nv-writer ring-clear &&
	./helper/test-nv-writer ring-revoke &&
	./helper/test-nv-writer ring-invalidate &&
	./helper/test-nv-writer ring-setperm
'

test_expect_success 'the TPM rejects an unsigned production-register extension over an inherited connection' '
	./helper/test-tpm-preopened >"$W/preopened.log" &&
	grep -qx "inherited-TPM: unsigned NV_Extend rejected by TPM; value unchanged" \
		"$W/preopened.log"
'

test_expect_success 'trusted status still reads the TPM after denied key access' '
	"$SHIRUDO_BIN" status --json >"$W/status.json" &&
	grep -q "\"chain_matches_eventlog\":true" "$W/status.json"
'

test_expect_success 'kernel signatures enforce nonce and command binding on the vTPM' '
	before=$("$SHIRUDO_BIN" status --json |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])") &&
	./helper/test-nv-cphash >"$W/cphash.log" &&
	grep -qx "PolicySigned: replay and corruption rejected; value unchanged" "$W/cphash.log" &&
	grep -qx "cpHash: authorized A; rejected B unchanged; extended A; scratch index removed" \
		"$W/cphash.log" &&
	"$SHIRUDO_BIN" status --json >"$W/status.json" &&
	after=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[\"tpm\"][\"chain\"])" \
		"$W/status.json") &&
	[ "$before" = "$after" ]
'

test_done
