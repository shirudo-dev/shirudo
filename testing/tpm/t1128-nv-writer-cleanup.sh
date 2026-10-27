#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

[ "${SHIRUDO_TEST_REGISTER_VM:-0}" = 1 ] ||
	test_skip_all "requires an uninitialized disposable VM"
[ "$(id -u)" = 0 ] && [ ! -e /run/shirudo/bpffs/identity ] &&
	[ ! -e /run/shirudo/bpffs/lsm_link ] || {
	echo "NV cleanup tests require root before shirudo init" >&2
	exit 1
}
R=./helper/test-nv-writer-cleanup
F=./fixtures/nv-writer-fault.bpf.o
[ -x "$R" ] || { echo "missing $R" >&2; exit 1; }

if [ "${SHIRUDO_TEST_NO_PKCS8:-0}" = 1 ]; then
	config="/boot/config-$(uname -r)"
	grep -qx '# CONFIG_PKCS8_PRIVATE_KEY_PARSER is not set' "$config" || {
		echo "parser-disabled test requires the booted kernel config at $config" >&2
		exit 1
	}
	test_expect_success 'PKCS#8 rejection leaves both keyrings unchanged on repeated attempts' '
		for attempt in 1 2 3; do
			"$R" no-pkcs8 || exit 1
		done
	'
	test_done
fi

: "${SHIRUDO_TEST_NV_CERT:?path to a test DER certificate is required}"
[ -s "$F" ] || { echo "missing $F" >&2; exit 1; }
mkdir -p /run/shirudo/bpffs
if mountpoint -q /run/shirudo/bpffs; then
	echo "NV cleanup tests require an unused private bpffs" >&2
	exit 1
fi
mount -t bpf -o nosuid,nodev,noexec bpf /run/shirudo/bpffs
cleanup() {
	status=$?
	trap - EXIT
	umount /run/shirudo/bpffs || status=1
	exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
"$R" enroll "$SHIRUDO_TEST_NV_CERT"

test_expect_success 'successful creation retains both links and can sign until explicit cleanup' '
	"$R" success
'

test_expect_success 'private-key import failure leaves both keyrings unchanged on repeated attempts' '
	for attempt in 1 2 3; do
		"$R" import "$F" || exit 1
	done
'

test_expect_success 'identity-map update failure rolls back the successfully created writer' '
	"$R" update "$F"
'

test_expect_success 'identity-map freeze failure rolls back the successfully created writer' '
	"$R" freeze "$F"
'

test_done
