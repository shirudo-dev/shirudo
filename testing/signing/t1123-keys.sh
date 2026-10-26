#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1123 -- the enrolled certificate set: the bundle's own-keyring
# certificate was installed as a second trusted certificate before
# init, so the bpf keyring holds two keys and a upatch signed by either
# loads.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

[ "$(keyring_mode)" = bpf ] ||
	test_skip_all "certificate staged in the user keyring; the set is enrolled in the bpf keyring only"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
OWN="$FIXTURES/shirudo-test-own-keyring.upatch"
OWN_CERT="$FIXTURES/own.der"
OWN_PIN=/run/shirudo/bpffs/upatches/shirudo-test-own-keyring/link
[ -s "$OWN" ] && [ -s "$OWN_CERT" ] || test_skip_all "missing own-keyring fixtures"
OWN_FP=$("$SHIRUDO_BIN" bpm key fingerprint "$OWN_CERT" 2>/dev/null)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
[ -e "/var/lib/shirudo/keys/trusted/$OWN_FP.der" ] ||
	test_skip_all "the own-keyring certificate is not installed as trusted"

test_expect_success 'status lists two enrolled certificates, the primary first by digest order' '
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
certs = d[\"certs\"]
assert len(certs) == 2, certs
assert sum(1 for c in certs if c[\"primary\"]) == 1, certs
assert any(c[\"fingerprint\"] == \"$OWN_FP\" for c in certs), certs
assert d[\"certs_revoked\"] == 0, d
"
'

test_expect_success 'the bpf keyring holds both keys' '
	grep -qE "keyring +\.bpf: 2" /proc/keys &&
	"$SHIRUDO_BIN" status --json | python3 -c "
import json, sys
assert json.load(sys.stdin)[\"certs_enrolled\"] == 2
"
'

test_expect_success 'the second certificate is a member by the primary vouch' '
	"$SHIRUDO_BIN" keys 2>/dev/null >"$W/keys" &&
	grep -q "^  $OWN_FP\$" "$W/keys" &&
	grep -q "vouched by" "$W/keys" &&
	[ -s "/var/lib/shirudo/keys/trusted/$OWN_FP.vouch" ]
'

test_expect_success 'the init record covers the set' '
	grep "\"type\":\"init\"" /var/lib/shirudo/eventlog | tail -1 |
		python3 -c "
import json, sys
r = json.loads(sys.stdin.read())
assert len(r[\"certs\"]) == 2, r
assert r[\"cert_sha256\"] not in r[\"certs\"], r
"
'

test_expect_success 'a upatch signed by the second key loads' '
	"$SHIRUDO_BIN" upatch load "$OWN" --no-precheck >/dev/null 2>&1 &&
	test -e "$OWN_PIN"
'

test_done
