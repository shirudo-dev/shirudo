#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6125 -- the TPM behind the device path is root's to replace: in a
# mount namespace of root's own a bind mount puts a character device of
# root's at /dev/tpmrm0. Refuse both another TPM and forged responses
# from a proxy forwarding the enrolled TPM's identity.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
SWTPM="$(dirname "$FIXTURES")/test-helpers/swtpm"
[ -x "$SWTPM/swtpm" ] || test_skip_all "no software TPM in the bundle"
NAME=shirudo-test-lifecycle
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME"
[ -s "$LOAD" ] && [ -s "$UNLOAD" ] || test_skip_all "missing lifecycle fixture"
[ ! -e "$PIN" ] || test_skip_all "$NAME is loaded"
W=/tmp/t6125
rm -rf "$W"
mkdir -p "$W"

cleanup() {
	[ -s "$W/pid" ] && kill "$(cat "$W/pid")" 2>/dev/null
	[ -s "$W/proxy-pid" ] && kill "$(cat "$W/proxy-pid")" 2>/dev/null
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$W"
}
trap cleanup EXIT

python3 functional/tamperproof/t6125-pty-tpm.py "$W" "$SWTPM" >"$W/out" 2>&1 &
echo $! >"$W/pid"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	[ -s "$W/slave" ] && break
	sleep 0.5
done
[ -s "$W/slave" ] || test_skip_all "the software TPM did not start"
SLAVE=$(cat "$W/slave")

chain() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tpm\"][\"chain\"])"
}
CHAIN=$(chain)

at_slave() {
	unshare -m sh -c "mount --make-rprivate / &&
		mount --bind $SLAVE /dev/tpmrm0 && $*"
}

test_expect_success 'the emulator answers at the device path' '
	at_slave python3 functional/tamperproof/t6125-pty-tpm.py probe /dev/tpmrm0
'

test_expect_success 'a load against a TPM init did not bind is refused' '
	rc=0; at_slave "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
		>/dev/null 2>"$W/load.err" || rc=$?;
	[ "$rc" != 0 ] &&
	grep -q "not the TPM init bound" "$W/load.err" &&
	[ ! -e "$PIN" ] &&
	[ "$(chain)" = "$CHAIN" ]
'

test_expect_success 'status against it is refused the same way' '
	! at_slave "$SHIRUDO_BIN" status >/dev/null 2>"$W/status.err" &&
	grep -q "not the TPM init bound" "$W/status.err"
'

test_expect_success 'the same load succeeds against the TPM init bound' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	[ -e "$PIN/link" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 &&
	[ ! -e "$PIN" ]
'

mkdir "$W/proxy" || exit 1
python3 functional/tamperproof/t6125-pty-tpm.py proxy "$W/proxy" >"$W/proxy.out" 2>&1 &
echo $! >"$W/proxy-pid"
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
	[ -s "$W/proxy/slave" ] && break
	sleep 0.5
done

test_expect_success 'the genuine TPM remains identifiable through the proxy' '
	[ -s "$W/proxy/slave" ] &&
	SLAVE=$(cat "$W/proxy/slave") &&
	at_slave env TSS2_LOG=all+TRACE \
		"$SHIRUDO_BIN" status --json >"$W/proxy-status.json" &&
	python3 -c "import json; assert json.load(open(\"$W/proxy-status.json\"))[\"tpm\"][\"chain_matches_eventlog\"] is True"
'

test_expect_success 'suppressing an extension cannot produce a successful unmeasured load' '
	SLAVE=$(cat "$W/proxy/slave") &&
	before=$(chain) &&
	lines=$(wc -l </var/lib/shirudo/eventlog) &&
	{
		rc=0
		at_slave "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck \
			>/dev/null 2>"$W/proxy-load.err" || rc=$?
		[ "$rc" != 0 ] &&
		grep -qx "proxy: suppressed NV_Extend" "$W/proxy.out" &&
		grep -q "NV_Extend.*rc=0x0007001b" "$W/proxy-load.err" &&
		[ ! -e "$PIN" ] &&
		[ "$(chain)" = "$before" ] &&
		[ "$(wc -l </var/lib/shirudo/eventlog)" = "$lines" ]
	}
'

test_done
