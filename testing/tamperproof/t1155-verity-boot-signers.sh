#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
verity_required() {
	printf 'Bail out! %s\n' "$*" >&2
	exit 1
}
target_guard

mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config ||
	verity_required "dm-verity image mode is not active"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"
case "$(uname -m)" in
x86_64|aarch64|riscv64) ;;
*) verity_required "no keyctl syscall numbers for this architecture" ;;
esac
: "${SHIRUDO_TEST_KEY_FIXTURES:=/root/verity-key-fixtures}"
for name in config-boot-keys config-live-new-key; do
	for suffix in img verity roothash p7s; do
		[ -r "$SHIRUDO_TEST_KEY_FIXTURES/$name.$suffix" ] ||
			verity_required "missing signed key fixture: $name.$suffix"
	done
done
for name in primary.der boot.der live.der boot.fingerprint live.fingerprint; do
	[ -r "$SHIRUDO_TEST_KEY_FIXTURES/$name" ] ||
		verity_required "missing public key fixture: $name"
done

if [ -n "${SHIRUDO_TEST_SIGNER_RESULTS:-}" ]; then
	work=$SHIRUDO_TEST_SIGNER_RESULTS
	mkdir -p "$work"
else
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT HUP INT TERM
fi
export SHIRUDO_BIN SHIRUDO_TEST_KEY_FIXTURES

test_expect_success 'boot enrolls the vouched signer and measures its signed CONFIG' '
	python3 tamperproof/t1155-verity-boot-signers.py initial "$work"
'

test_expect_success 'a signed CONFIG needing a new live signer refuses before changes' '
	python3 tamperproof/t1155-verity-boot-signers.py new-signer "$work"
'

test_expect_success 'the current CONFIG with two boot-enrolled signers is a no-op' '
	python3 tamperproof/t1155-verity-boot-signers.py repeat "$work"
'

test_done
