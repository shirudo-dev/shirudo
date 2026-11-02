#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9106 -- signed policy labels enforce policy graphs and are removable.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
LOAD="$FIXTURES/shirudo-test-policy-exec-graph.upatch"
UNLOAD="$FIXTURES/shirudo-test-policy-exec-graph.unload.upatch"
WORK=/tmp/shirudo-policy-exec-graph
HELPER=./end2end/policy-exec
POLICY_PROBE=/run/shirudo/runtime/usr/bin/shirudo-policy-probe
E2E=$PWD/../build/test-vm/end2end
OUT=/mnt/shirudo-out/end2end

[ -s "$LOAD" ] && [ -s "$UNLOAD" ] ||
	test_skip_all "missing policy exec graph fixture"
[ -x "$HELPER" ] || test_skip_all "policy exec graph helper is missing"
[ -x "$POLICY_PROBE" ] || test_skip_all "runtime policy probe is missing"
[ -s "$E2E/nonce" ] && [ -d "$OUT" ] ||
	test_skip_all "end-to-end evidence destination is missing"
NONCE=$(cat "$E2E/nonce")

rm -rf "$WORK"
mkdir -p "$WORK"
cp "$HELPER" "$WORK/exec-1"
cp "$HELPER" "$WORK/exec-2"
cp "$HELPER" "$WORK/exec-4"
cp "$HELPER" "$WORK/unlabeled"
cp "$HELPER" "$WORK/socket-a"
cp "$HELPER" "$WORK/socket-b"
chmod 0755 "$WORK"/*

"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ||
	exit 1
if "$WORK/unlabeled" verify; then
	UNLABELED_RESULT=ok
else
	UNLABELED_RESULT=failed
fi
"$WORK/exec-1" run "$UNLABELED_RESULT" || exit 1
"$SHIRUDO_BIN" attest --nonce="$NONCE" --out="$OUT/evidence.json" ||
	exit 1
"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 ||
	exit 1
"$POLICY_PROBE" remove-policy "$WORK/exec-1" || exit 1
