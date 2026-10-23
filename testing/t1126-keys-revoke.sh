#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1126 -- a signed CONFIG owns signer revocation. A live revoke is
# refused without changing the boot-enrolled keyring or loaded upatch.

cd "$(dirname "$0")"
. ./integration-lib.sh
target_guard

[ "$(keyring_mode)" = bpf ] ||
	test_skip_all "certificate staged in the user keyring; revocation needs the bpf keyring"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
OWN="$FIXTURES/shirudo-test-own-keyring.upatch"
OWN_CERT="$FIXTURES/own.der"
OWN_PIN=/run/shirudo/bpffs/upatches/shirudo-test-own-keyring/link
ARCHIVE=/var/lib/shirudo/upatches/shirudo-test-own-keyring.upatch
[ -s "$OWN" ] && [ -s "$OWN_CERT" ] || test_skip_all "missing own-keyring fixtures"
OWN_FP=$("$SHIRUDO_BIN" bpm key fingerprint "$OWN_CERT" 2>/dev/null)
PRIMARY_FP=$("$SHIRUDO_BIN" bpm key fingerprint /var/lib/shirudo/keys/cert.der 2>/dev/null)
[ -e "/var/lib/shirudo/keys/trusted/$OWN_FP.der" ] ||
	test_skip_all "the own-keyring certificate is not a trusted member"
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

events_of_type() {
	grep -c "\"type\":\"$1\"" /var/lib/shirudo/eventlog || :
}

test_expect_success 'the upatch signed by the second key is loaded' '
	if ! [ -e "$OWN_PIN" ]; then
		"$SHIRUDO_BIN" upatch load "$OWN" --no-precheck >/dev/null 2>&1
	fi &&
	[ -e "$OWN_PIN" ] && [ -s "$ARCHIVE" ]
'

test_expect_success 'live revocation is refused without changing the signer or upatch' '
	before_rev=$(events_of_type key_revoke) &&
	! "$SHIRUDO_BIN" keys revoke "$OWN_FP" >"$W/out" 2>"$W/err" &&
	grep -q "signed config image" "$W/err" &&
	[ -e "$OWN_PIN" ] && [ -s "$ARCHIVE" ] &&
	[ "$(events_of_type key_revoke)" = "$before_rev" ] &&
	grep -qE "keyring +\.bpf: 2" /proc/keys
'

test_expect_success 'the bpf keyring and signed trusted set still contain both keys' '
	[ "$(status_field certs_enrolled)" = 2 ] &&
	[ "$(status_field certs_revoked)" = 0 ] &&
	[ -s "/var/lib/shirudo/keys/trusted/$OWN_FP.der" ] &&
	[ -s "/var/lib/shirudo/keys/trusted/$OWN_FP.vouch" ] &&
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert any(c[\"fingerprint\"] == \"$OWN_FP\" for c in d[\"certs\"]), d
"
'

test_expect_success 'the signed upatch remains loaded and archived' '
	[ -e "$OWN_PIN" ] && [ -s "$ARCHIVE" ]
'

test_expect_success 'repeated live revocation and live signer addition are refused' '
	! "$SHIRUDO_BIN" keys revoke "$OWN_FP" >/dev/null 2>&1 &&
	! "$SHIRUDO_BIN" keys add "$OWN_CERT" --vouch "$FIXTURES/own.vouch" >/dev/null 2>&1 &&
	[ "$(status_field certs_enrolled)" = 2 ]
'

test_expect_success 'live revocation of the primary is refused too' '
	! "$SHIRUDO_BIN" keys revoke "$PRIMARY_FP" >/dev/null 2>&1 &&
	grep -qE "keyring +\.bpf: 2" /proc/keys
'

test_done
