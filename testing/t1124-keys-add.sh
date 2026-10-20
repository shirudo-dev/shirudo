#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1124 -- `keys add` on a live target: the bundle's third certificate
# joins the trusted set on disk with the vouch the primary signed for
# it, and the bpf keyring stays as the boot sealed it.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

[ "$(keyring_mode)" = bpf ] ||
	test_skip_all "certificate staged in the user keyring; the set is enrolled in the bpf keyring only"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
THIRD="$FIXTURES/third.der"
VOUCH="$FIXTURES/third.vouch"
OWN_VOUCH="$FIXTURES/own.vouch"
[ -s "$THIRD" ] && [ -s "$VOUCH" ] && [ -s "$OWN_VOUCH" ] ||
	test_skip_all "missing third-certificate fixtures"
THIRD_FP=$("$SHIRUDO_BIN" bpm key fingerprint "$THIRD" 2>/dev/null)
TRUSTED=/var/lib/shirudo/keys/trusted
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

status_field() {
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
v = d[\"$1\"]
print(len(v) if isinstance(v, list) else v)
"
}

test_expect_success 'a vouch made for another certificate is refused' '
	! "$SHIRUDO_BIN" keys add "$THIRD" --vouch "$OWN_VOUCH" >/dev/null 2>&1 &&
	! [ -e "$TRUSTED/$THIRD_FP.der" ] &&
	[ "$(status_field certs)" = 2 ]
'

test_expect_success 'the vouched certificate joins the trusted set on disk' '
	out=$("$SHIRUDO_BIN" keys add "$THIRD" --vouch "$VOUCH" 2>/dev/null) &&
	[ "$out" = "$THIRD_FP" ] &&
	cmp -s "$THIRD" "$TRUSTED/$THIRD_FP.der" &&
	cmp -s "$VOUCH" "$TRUSTED/$THIRD_FP.vouch" &&
	[ "$(status_field certs)" = 3 ] &&
	[ "$(status_field certs_unvouched)" = 0 ]
'

test_expect_success 'the bpf keyring keeps the set the boot sealed' '
	[ "$(status_field certs_enrolled)" = 2 ] &&
	grep -qE "keyring +\.bpf: 2" /proc/keys
'

test_expect_success 'adding it again changes nothing' '
	out=$("$SHIRUDO_BIN" keys add "$THIRD" --vouch "$VOUCH" 2>/dev/null) &&
	[ "$out" = "$THIRD_FP" ] &&
	[ "$(status_field certs)" = 3 ]
'

test_expect_success 'keys lists the member with its voucher' '
	"$SHIRUDO_BIN" keys 2>/dev/null >"$W/keys" &&
	grep -q "^  $THIRD_FP\$" "$W/keys" &&
	grep -q "3 members, 0 revoked, 0 unvouched" "$W/keys" &&
	grep -q "^Keyring (.bpf):" "$W/keys"
'

test_done
