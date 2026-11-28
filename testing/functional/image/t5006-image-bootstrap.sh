#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
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

test_expect_success 'two config verification keys preserve their order and runtime root' '
	cp "$WORK/runtime.conf" "$WORK/overlap.conf" &&
	printf "config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert-2.der\n" \
		>>"$WORK/overlap.conf" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/overlap.conf" >"$WORK/result" &&
	grep -qx "root=$root" "$WORK/result" &&
	grep -qx "certificates=2" "$WORK/result" &&
	sed -n "s/^certificate=//p" "$WORK/result" >"$WORK/certificates" &&
	printf "%s\n" /run/shirudo/runtime/etc/shirudo/config-cert.der \
		/run/shirudo/runtime/etc/shirudo/config-cert-2.der >"$WORK/expected" &&
	cmp "$WORK/certificates" "$WORK/expected"
'

test_expect_success 'duplicate config verification paths are rejected' '
	cp "$WORK/runtime.conf" "$WORK/bad.conf" &&
	printf "config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der\n" \
		>>"$WORK/bad.conf" &&
	! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf"
'

test_expect_success 'an invalid later verification key rejects the whole bootstrap config' '
	cp "$WORK/runtime.conf" "$WORK/bad.conf" &&
	printf "config.verification_key = /etc/attacker.der\n" >>"$WORK/bad.conf" &&
	! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf"
'

test_expect_success 'config verification keys have a bounded count' '
	python3 - ../util/keys.h "$WORK/max.conf" "$WORK/too-many.conf" <<"PYTEST" &&
import re, sys
from pathlib import Path
limit = int(re.search(r"#define KEYS_MAX\s+(\d+)", Path(sys.argv[1]).read_text())[1])
lines = [f"config.verification_key = /run/shirudo/runtime/keys/config-{i}.der\n"
         for i in range(limit + 1)]
Path(sys.argv[2]).write_text("".join(lines[:-1]))
Path(sys.argv[3]).write_text("".join(lines))
PYTEST
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/max.conf" >/dev/null &&
	! "$H" bootstrap "$WORK/initrd.conf" "$WORK/too-many.conf"
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

test_expect_success 'the config NvPCR replaces the config PCR, as the runtime image says' '
	cp "$WORK/runtime.conf" "$WORK/nvpcr.conf" &&
	printf "config.nvpcr = shirudo-config\n" >>"$WORK/nvpcr.conf" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/nvpcr.conf" >"$WORK/result" &&
	grep -qx "pcr=25267716" "$WORK/result" &&
	for value in other shirudo-config- 0x01818e04 ""; do
		printf "config.nvpcr = %s\n" "$value" >"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'the runtime image selects the enforcement mode, strict by default' '
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/runtime.conf" >"$WORK/result" &&
	grep -qx "enforcement=strict" "$WORK/result" &&
	for mode in strict shared; do
		cp "$WORK/runtime.conf" "$WORK/mode.conf" &&
		printf "enforcement.mode = %s\n" "$mode" >>"$WORK/mode.conf" &&
		"$H" bootstrap "$WORK/initrd.conf" "$WORK/mode.conf" \
			>"$WORK/result" &&
		grep -qx "enforcement=$mode" "$WORK/result" || exit 1
	done
'

test_expect_success 'the enforcement mode comes from the runtime image alone' '
	cp "$WORK/initrd.conf" "$WORK/bad.conf" &&
	printf "enforcement.mode = shared\n" >>"$WORK/bad.conf" &&
	! "$H" bootstrap "$WORK/bad.conf" &&
	for setting in "enforcement.mode = loose" "enforcement.mode =" \
		"enforcement.mode = Shared" "enforcement.unknown = shared"; do
		cp "$WORK/runtime.conf" "$WORK/bad.conf" &&
		printf "%s\n" "$setting" >>"$WORK/bad.conf" &&
		! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf" || exit 1
	done
'

test_expect_success 'a runtime bootstrap read again sets the mode afresh' '
	cp "$WORK/runtime.conf" "$WORK/shared.conf" &&
	printf "enforcement.mode = shared\n" >>"$WORK/shared.conf" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/shared.conf" \
		"$WORK/shared.conf" >"$WORK/result" &&
	grep -qx "enforcement=shared" "$WORK/result" &&
	"$H" bootstrap "$WORK/initrd.conf" "$WORK/shared.conf" \
		"$WORK/runtime.conf" >"$WORK/result" &&
	grep -qx "enforcement=strict" "$WORK/result"
'

test_expect_success 'a repeated enforcement mode is rejected' '
	cp "$WORK/runtime.conf" "$WORK/bad.conf" &&
	printf "enforcement.mode = strict\nenforcement.mode = shared\n" \
		>>"$WORK/bad.conf" &&
	! "$H" bootstrap "$WORK/initrd.conf" "$WORK/bad.conf"
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
