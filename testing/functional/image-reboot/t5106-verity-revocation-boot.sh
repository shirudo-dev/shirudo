#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t5106 -- a config that revokes a BPF signer, staged and then activated
# by the next boot. The boot enrolls no revoked key, purges the archive of
# what that key signed before the restore and binds the register from the
# initrd as any boot does.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
: "${SHIRUDO_TEST_KEY_FIXTURES:?signed key fixtures are required}"
: "${SHIRUDO_TEST_RESULTS:?results that outlive the reboot are required}"
work=$SHIRUDO_TEST_RESULTS/revocation-boot
mkdir -p "$work"
export SHIRUDO_BIN SHIRUDO_TEST_KEY_FIXTURES
py=functional/image-reboot/t5106-verity-revocation-boot.py

case ${SHIRUDO_TEST_BOOT:-1} in
1)
	test_expect_success 'the boot signer loads a upatch that is pinned and archived' '
		python3 "$py" load "$work"
	'
	test_expect_success 'staging the revocation leaves this boot as it is' '
		python3 "$py" stage "$work"
	'
	;;
2)
	test_expect_success 'the next boot activates the staged config from the initrd' '
		python3 "$py" booted "$work"
	'
	test_expect_success 'the boot enrolled no revoked signer and restored nothing it signed' '
		python3 "$py" purged "$work"
	'
	test_expect_success 'a load the revoked signer signed is refused and changes nothing' '
		python3 "$py" refused "$work"
	'
	;;
*)
	test_expect_success 'the test knows the boot it runs in' 'false'
	;;
esac
test_done
