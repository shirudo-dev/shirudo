#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t5107 -- an archive no signer can be read from, as a torn write leaves
# one, and a config with revocation records. A live update refuses before
# it changes anything, since it cannot tell whether the revoked key signed
# what runs. The next boot enrolls no revoked key, so it goes on past the
# file: init completes and the upatch of that archive is not restored.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
: "${SHIRUDO_TEST_KEY_FIXTURES:?signed key fixtures are required}"
: "${SHIRUDO_TEST_FIXTURES_DIR:?signed upatch fixtures are required}"
: "${SHIRUDO_TEST_RESULTS:?results that outlive the reboot are required}"
[ -x /run/shirudo/runtime/usr/bin/shirudo-image-fault ] ||
	test_skip_all "the runtime image has no fault helper"
work=$SHIRUDO_TEST_RESULTS/revocation-archive
mkdir -p "$work"
export SHIRUDO_BIN SHIRUDO_TEST_KEY_FIXTURES SHIRUDO_TEST_FIXTURES_DIR
py=functional/image-reboot/t5107-verity-revocation-archive.py

case ${SHIRUDO_TEST_BOOT:-1} in
1)
	test_expect_success 'a loaded upatch has its archive cut short' '
		python3 "$py" tear "$work"
	'
	test_expect_success 'a live revocation refuses the archive and changes nothing' '
		python3 "$py" live "$work"
	'
	;;
2)
	test_expect_success 'the boot that revokes goes on past the archive' '
		python3 "$py" booted "$work"
	'
	test_expect_success 'status and the keepalive show a loaded set without the upatch' '
		python3 "$py" reported "$work"
	'
	test_expect_success 'a live revocation still refuses the archive after the boot' '
		python3 "$py" live-again "$work"
	'
	;;
*)
	test_expect_success 'the test knows the boot it runs in' 'false'
	;;
esac
test_done
