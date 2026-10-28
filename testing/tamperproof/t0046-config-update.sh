#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

H=${SHIRUDO_TEST_CONFIG_HELPER:-$(pwd)/helper/test-config-update}
SIM=$(pwd)/helper/tpmsim-cmd
[ -x "$H" ] || test_skip_all "test-config-update helper not built"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

field() {
	sed -n "s/^$2=//p" "$1"
}

fresh() {
	mkdir -m 700 "$WORK/$1"
	"$H" "$WORK/$1" boot A >"$WORK/$1.out"
}

crash_update() {
	SHIRUDO_TEST_CONFIG_CRASH=$2 "$H" "$WORK/$1" update B \
		>"$WORK/$1.crash" 2>&1
	rc=$?
	[ "$rc" = 99 ]
}

test_expect_success 'event hash binds domain, event kind and binary root' '
	"$H" "$WORK" describe A >"$WORK/hash" &&
	python3 - "$WORK/hash" <<"PYTEST"
import hashlib, sys
v = dict(line.rstrip().split("=", 1) for line in open(sys.argv[1]))
root = bytes.fromhex(v["root_hash"])
assert len(root) == 32
assert v["boot_event"] == hashlib.sha256(b"shirudo-config-root-v1\0" +
                                        (1).to_bytes(4, "big") + root).hexdigest()
PYTEST
'

test_expect_success 'static PCR policy excludes resettable PCRs and boot anchors' '
	for pcr in 0 1 7 8 10 12 13 14 15; do
		mkdir -m 700 "$WORK/pcr-$pcr" &&
		"$H" "$WORK/pcr-$pcr" boot A "$pcr" >/dev/null || exit 1
	done &&
	for pcr in 9 11 16 23 24 4294967295; do
		mkdir -m 700 "$WORK/pcr-$pcr" &&
		! "$H" "$WORK/pcr-$pcr" boot A "$pcr" >/dev/null || exit 1
	done
'

test_expect_success 'boot completion, idempotence and live updates have exact event counts' '
	fresh normal &&
	[ "$(field "$WORK/normal.out" pending)" = 0 ] &&
	"$H" "$WORK/normal" boot A >/dev/null &&
	"$H" "$WORK/normal" update B >/dev/null &&
	"$H" "$WORK/normal" update A >/dev/null &&
	"$H" "$WORK/normal" update A >"$WORK/same" &&
	[ "$(field "$WORK/same" extends)" = 3 ] &&
	[ "$(field "$WORK/same" events)" = 3 ] &&
	"$H" "$WORK/normal" check >/dev/null
'

test_expect_success 'live update cannot create the initial BOOT selection' '
	mkdir -m 700 "$WORK/no-boot" &&
	! "$H" "$WORK/no-boot" update B >"$WORK/no-boot.out" &&
	[ "$(field "$WORK/no-boot.out" extends)" = 0 ]
'

for failure in PREPARE READ; do
	test_expect_success "failure before pending intent ($failure) leaves current selection healthy" '
		fresh bad-'"$failure"' &&
		! env SHIRUDO_TEST_CONFIG_'"$failure"'_FAIL=1 "$H" "$WORK/bad-'"$failure"'" update B >"$WORK/failure" &&
		[ "$(field "$WORK/failure" extends)" = 1 ] &&
		[ "$(field "$WORK/failure" pending)" = 0 ] &&
		"$H" "$WORK/bad-'"$failure"'" check >/dev/null
	'
done

for response in before ambiguous drift; do
	test_expect_success "TPM $response response leaves pending state and never retries in this boot" '
		fresh tpm-'"$response"' &&
		! SHIRUDO_TEST_CONFIG_EXTEND='"$response"' "$H" "$WORK/tpm-'"$response"'" update B >"$WORK/failed" &&
		[ "$(field "$WORK/failed" pending)" = 1 ] &&
		! "$H" "$WORK/tpm-'"$response"'" check >/dev/null &&
		! "$H" "$WORK/tpm-'"$response"'" update B >/dev/null &&
		! "$H" "$WORK/tpm-'"$response"'" boot B >"$WORK/retry" &&
		[ "$(field "$WORK/retry" extends)" = 2 ]
	'
done

test_expect_success 'boot remains pending until restore and NV initialization explicitly complete' '
	mkdir -m 700 "$WORK/boot-pending" &&
	SHIRUDO_TEST_CONFIG_BOOT_PENDING=1 "$H" "$WORK/boot-pending" boot A >"$WORK/boot-pending.out" &&
	[ "$(field "$WORK/boot-pending.out" pending)" = 1 ] &&
	! "$H" "$WORK/boot-pending" check >/dev/null &&
	! "$H" "$WORK/boot-pending" complete >/dev/null &&
	! "$H" "$WORK/boot-pending" boot A >/dev/null
'

test_expect_success 'activation failure leaves pending state and blocks further changes' '
	fresh partial &&
	! SHIRUDO_TEST_CONFIG_ACTIVATE_FAIL=1 "$H" "$WORK/partial" update B >/dev/null &&
	! "$H" "$WORK/partial" check >/dev/null &&
	! "$H" "$WORK/partial" update A >/dev/null
'

test_expect_success 'PCR drift and a changed PCR allocation refuse live updates' '
	fresh drift && "$H" "$WORK/drift" drift >/dev/null &&
	! "$H" "$WORK/drift" check >/dev/null &&
	! "$H" "$WORK/drift" update B >/dev/null &&
	fresh pcr-change && ! "$H" "$WORK/pcr-change" update B 14 >/dev/null
'

for action in reset restart; do
	test_expect_success "$action requires a new BOOT event for the same root" '
		fresh epoch-'"$action"' &&
		"$H" "$WORK/epoch-'"$action"'" '"$action"' >/dev/null &&
		! "$H" "$WORK/epoch-'"$action"'" check >/dev/null &&
		"$H" "$WORK/epoch-'"$action"'" boot A >"$WORK/epoch" &&
		[ "$(field "$WORK/epoch" extends)" = 2 ] &&
		[ "$(field "$WORK/epoch" kind)" = 1 ]
	'
done

test_expect_success 'process death after measurement leaves a persistent pending latch' '
	fresh crash && crash_update crash 2 &&
	! "$H" "$WORK/crash" check >/dev/null &&
	! "$H" "$WORK/crash" update B >/dev/null &&
	! "$H" "$WORK/crash" boot B >"$WORK/retry" &&
	[ "$(field "$WORK/retry" extends)" = 2 ]
'

test_expect_success 'death before pending rename leaves the completed selection usable' '
	fresh pre-pending && crash_update pre-pending 6 &&
	"$H" "$WORK/pre-pending" check >/dev/null
'

test_expect_success 'death after durable completion leaves a healthy selection' '
	fresh completed && crash_update completed 5 &&
	"$H" "$WORK/completed" check >"$WORK/completed.out" &&
	[ "$(field "$WORK/completed.out" extends)" = 2 ] &&
	[ "$(field "$WORK/completed.out" pending)" = 0 ]
'

test_expect_success 'a truncated completed eventlog is rejected' '
	fresh truncated-log &&
	python3 - "$WORK/truncated-log/events" <<"PY" &&
import os, sys
os.truncate(sys.argv[1], os.path.getsize(sys.argv[1]) - 1)
PY
	! "$H" "$WORK/truncated-log" check >/dev/null
'

test_expect_success 'corrupted state fails without any extension or activation' '
	fresh corrupt-state &&
	python3 - "$WORK/corrupt-state/state" <<"PY" &&
from pathlib import Path
import sys
p = Path(sys.argv[1]); b = bytearray(p.read_bytes()); b[100] ^= 1; p.write_bytes(b)
PY
	! "$H" "$WORK/corrupt-state" check >"$WORK/corrupt-state.out" &&
	[ "$(field "$WORK/corrupt-state.out" extends)" = 1 ] &&
	[ "$(field "$WORK/corrupt-state.out" activations)" = 1 ]
'

test_expect_success 'a stale temporary-file symlink cannot redirect durable writes' '
	fresh stale-tmp && printf untouched >"$WORK/victim" &&
	ln -s "$WORK/victim" "$WORK/stale-tmp/.state.tmp" &&
	"$H" "$WORK/stale-tmp" update B >/dev/null &&
	[ "$(cat "$WORK/victim")" = untouched ]
'

test_expect_success 'a state symlink and a hard-linked state are refused' '
	fresh state-link && mv "$WORK/state-link/state" "$WORK/saved-state" &&
	ln -s "$WORK/saved-state" "$WORK/state-link/state" &&
	! "$H" "$WORK/state-link" check >/dev/null &&
	rm "$WORK/state-link/state" &&
	ln "$WORK/saved-state" "$WORK/state-link/state" &&
	! "$H" "$WORK/state-link" check >/dev/null
'

test_expect_success 'eventlog and lock symlinks are refused before measurement' '
	mkdir -m 700 "$WORK/event-link" "$WORK/lock-link" &&
	printf untouched >"$WORK/linked-victim" &&
	ln -s "$WORK/linked-victim" "$WORK/event-link/events" &&
	! "$H" "$WORK/event-link" boot A >"$WORK/event-link.out" &&
	ln -s "$WORK/linked-victim" "$WORK/lock-link/lock" &&
	! "$H" "$WORK/lock-link" boot A >/dev/null &&
	[ "$(cat "$WORK/linked-victim")" = untouched ] &&
	[ "$(field "$WORK/event-link.out" extends)" = 0 ]
'

test_expect_success 'missing, symlinked and world-writable state directories are refused' '
	! "$H" "$WORK/missing" boot A >/dev/null &&
	mkdir -m 700 "$WORK/real-dir" &&
	ln -s "$WORK/real-dir" "$WORK/dir-link" &&
	! "$H" "$WORK/dir-link" boot A >/dev/null &&
	chmod 777 "$WORK/real-dir" &&
	! "$H" "$WORK/real-dir" boot A >/dev/null
'

test_expect_success 'a second writer cannot acquire the same operation lock' '
	fresh locked &&
	! "$H" "$WORK/locked" lock >"$WORK/locked.out" &&
	[ "$(field "$WORK/locked.out" rc)" = -11 ]
'

test_expect_success 'a command waits for the operation lock another one holds' '
	command -v flock >/dev/null 2>&1 || exit 0;
	fresh waiting &&
	{ flock "$WORK/waiting/lock" sleep 1 & holder=$!; } &&
	sleep 0.3 &&
	SHIRUDO_TEST_CONFIG_LOCK_WAIT_MS=10000 "$H" "$WORK/waiting" boot A \
		>"$WORK/waiting.out" 2>"$WORK/waiting.err" &&
	wait "$holder" &&
	[ "$(field "$WORK/waiting.out" rc)" = 0 ]
'

test_expect_success 'the wait for the operation lock ends with the lock still held' '
	command -v flock >/dev/null 2>&1 || exit 0;
	fresh held &&
	{ flock "$WORK/held/lock" sleep 3 & holder=$!; } &&
	sleep 0.3 &&
	! SHIRUDO_TEST_CONFIG_LOCK_WAIT_MS=500 "$H" "$WORK/held" boot A \
		>"$WORK/held.out" 2>"$WORK/held.err" &&
	[ "$(field "$WORK/held.out" rc)" = -11 ] &&
	grep -q "still holds the config operation lock" "$WORK/held.err" &&
	wait "$holder"
'

test_expect_success 'seal failures prevent trusted journal creation' '
	mkdir -m 700 "$WORK/no-seal" &&
	! SHIRUDO_TEST_CONFIG_SEAL_FAIL=1 "$H" "$WORK/no-seal" boot A >/dev/null &&
	test ! -e "$WORK/no-seal/state"
'

if [ -x "$SIM" ]; then
	test_expect_success 'actual TPM values match independently computed root events' '
		mkdir -m 700 "$WORK/real-tpm" &&
		SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm" SHIRUDO_TEST_CONFIG_TPM=1 \
			"$H" "$WORK/real-tpm" boot A >"$WORK/real-a" &&
		SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm" SHIRUDO_TEST_CONFIG_TPM=1 \
			"$H" "$WORK/real-tpm" update B >"$WORK/real-b" &&
		python3 - "$WORK/real-b" <<"PYTEST"
import hashlib, sys
pcr = bytes(32)
for kind, root in [(1, b"A" * 32), (2, b"B" * 32)]:
    event = hashlib.sha256(b"shirudo-config-root-v1\0" + kind.to_bytes(4, "big") + root).digest()
    pcr = hashlib.sha256(pcr + event).digest()
f = dict(line.rstrip().split("=", 1) for line in open(sys.argv[1]))
assert f["pcr_value"] == pcr.hex() and f["extends"] == "2"
PYTEST
	'
	test_expect_success 'ambiguous real TPM completion refuses retries without another extension' '
		! SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm" SHIRUDO_TEST_CONFIG_TPM=1 \
		SHIRUDO_TEST_CONFIG_EXTEND=ambiguous "$H" "$WORK/real-tpm" update C >/dev/null &&
		! SHIRUDO_TPM_TCTI="cmd:$SIM $WORK/tpm" SHIRUDO_TEST_CONFIG_TPM=1 \
			"$H" "$WORK/real-tpm" update C >"$WORK/no-retry" &&
		[ "$(field "$WORK/no-retry" extends)" = 3 ]
	'
else
	test_skip_all "libtpms helper required for actual PCR coverage"
fi

test_done
