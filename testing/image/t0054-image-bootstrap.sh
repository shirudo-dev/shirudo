#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./test-lib.sh

H=${SHIRUDO_TEST_IMAGE_CONFIG_HELPER:-./helper/test-image-config}
[ -x "$H" ] || test_skip_all "test-image-config helper not built"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

root=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
printf "runtime.image = /var/lib/shirudo/runtime\nruntime.root_hash = %s\n" \
	"$root" >"$WORK/initrd.conf"
printf "config.image = /var/lib/shirudo/images/initial\nconfig.pcr = 15\n" \
	>"$WORK/runtime.conf"
printf "config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der\n" \
	>>"$WORK/runtime.conf"

test_expect_success 'runtime settings preserve the root authenticated by the initrd' '
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/runtime.conf" >"$WORK/result" &&
	grep -qx "runtime=/var/lib/shirudo/runtime" "$WORK/result" &&
	grep -qx "root=$root" "$WORK/result" &&
	grep -qx "config=/var/lib/shirudo/images/initial" "$WORK/result" &&
	grep -qx "certificate=/run/shirudo/runtime/etc/shirudo/config-cert.der" "$WORK/result" &&
	grep -qx "pcr=15" "$WORK/result"
'

test_expect_success 'runtime settings cannot replace the executable image or its root' '
	for setting in "runtime.image = /var/lib/shirudo/other" \
		"runtime.root_hash = $root"; do
		printf "%s\n" "$setting" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'duplicate runtime paths and hashes are rejected in the initrd' '
	for setting in "runtime.image = /var/lib/shirudo/other" \
		"runtime.root_hash = $root"; do
		cp "$WORK/initrd.conf" "$WORK/bad.conf" &&
		printf "%s\n" "$setting" >>"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'image paths reject relative paths and parent traversal' '
	for path in relative /var/../outside /var/./image /var//image /var/.. /; do
		for key in runtime.image config.image; do
			printf "%s = %s\n" "$key" "$path" >"$WORK/bad.conf" &&
			! "$H" bootstrap "$WORK/bad.conf" || exit 1
		done
	done
'

test_expect_success 'config verification certificates must come from the runtime image' '
	for path in /etc/cert.der /run/shirudo/runtime-other/cert.der \
		/run/shirudo/runtime/../cert.der; do
		printf "config.verification_key = %s\n" "$path" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'config PCR rejects boot PCRs and resettable PCRs' '
	for pcr in 9 11 16 23 24 -1 invalid 99999999999999999999999999; do
		printf "config.pcr = %s\n" "$pcr" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'unknown image settings and malformed lines are rejected' '
	for setting in "runtime.unknown = value" "config.unknown = value" "missing equals"; do
		printf "%s\n" "$setting" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'malformed hashes and oversized lines are rejected' '
	for hash in short "${root}00" "${root%?}x"; do
		printf "runtime.root_hash = %s\n" "$hash" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/bad.conf" || exit 1
	done &&
	python3 -c "print(\"#\" + \"x\" * 5000)" >"$WORK/bad.conf" &&
	! "$H" bootstrap "$WORK/bad.conf"
'

test_expect_success 'unrelated settings remain available to the regular config reader' '
	printf "# comment\neventlog.max_bytes = 12345\n\n" >"$WORK/other.conf" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/other.conf" >"$WORK/result" &&
	grep -qx "root=$root" "$WORK/result"
'

test_done
