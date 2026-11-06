#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6126 -- a kexec hands the machine to a kernel and an initrd of root's
# choosing with the TPM as it is: PCRs 9 and 11 keep this boot's values,
# the register keeps this boot's history, and the evidence of this boot
# vouches for whatever runs after. Available load system calls must be
# refused and counted as Kexec. The probe loads nothing it does not
# unload again and executes nothing.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
IMAGE=
for candidate in /boot/vmlinuz /boot/vmlinuz-*; do
	if [ -f "$candidate" ]; then
		IMAGE=$candidate
		break
	fi
done
[ -n "$IMAGE" ] || test_skip_all "no kernel image under /boot"
EPERM=1
ENOSYS=38

counter() {
	"$SHIRUDO_BIN" status --json 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin)[\"tamper_attempts\"][\"counters\"][\"Kexec\"])"
}

test_expect_success 'available kexec load syscalls are refused and counted' '
	before=$(counter) &&
	set -- $(python3 functional/tamperproof/t6126-kexec.py "$IMAGE") || return 1
	[ "$2" = "$EPERM" ] || return 1
	expected=1
	if [ "$1" = "$EPERM" ]; then
		expected=2
	elif [ "$1" != "$ENOSYS" ]; then
		return 1
	fi
	[ "$(counter)" -ge $((before + expected)) ]
'

test_done
