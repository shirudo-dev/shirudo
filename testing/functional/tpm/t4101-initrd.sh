#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t4101 -- the production configuration: init ran from the initrd,
# the root file system's run adopted its record, and the register was
# bound while PCR 11 still held the enter-initrd phase.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard

STATUS=$(mktemp)
trap 'rm -f "$STATUS"' EXIT
"$SHIRUDO_BIN" status --json >"$STATUS" 2>/dev/null || test_skip_all "status failed"
# A top-level field, or one of the tpm object as tpm.<field>.
status_field() {
	python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print(d if d is not None else "")
' "$STATUS" "$1"
}
[ "$(status_field tpm.bound_in)" = initrd ] ||
	test_skip_all "init did not run from the initrd (bound_in=$(status_field tpm.bound_in))"

# systemd measures the initrd phases into PCR 11 only for a measured
# UKI boot; a kernel booted directly, as in the test VM, leaves PCR 11
# at its boot value and the binding has only the PCR 9 anchor.
PHASE_BEFORE=$(status_field tpm.phase_before)
PHASE_MEASURED=1
[ "$PHASE_BEFORE" != "$(printf '%064d' 0)" ] || PHASE_MEASURED=0

test_expect_success 'status reports an attached LSM and a BPF keyring' '
	[ -z "$(status_field mode)" ] &&
	[ "$(status_field lsm_attached)" = True ] &&
	[ "$(status_field keyring_mode)" = bpf ]
'

test_expect_success 'the initrd unit ran and completed init' '
	journalctl -b -u shirudo-initrd.service --no-pager 2>/dev/null |
		grep -q "init: complete"
'

test_expect_success 'the journal holds a message of the initrd run once' '
	n=$(journalctl -b -u shirudo-initrd.service --no-pager 2>/dev/null |
		grep -c "init: complete") &&
	[ "$n" = 1 ]
'

test_expect_success 'the root adopted the initrd record into the eventlog' '
	test ! -e /run/shirudo/eventlog.pending &&
	grep -q "\"bound_in\":\"initrd\"" /var/lib/shirudo/eventlog
'

test_expect_success 'PCR 11 moved on after the binding, when a phase was measured' '
	now=$(tr "A-F" "a-f" </sys/class/tpm/tpm0/pcr-sha256/11) &&
	[ -n "$PHASE_BEFORE" ] && [ -n "$now" ] &&
	if [ "$PHASE_MEASURED" = 1 ]; then
		[ "$PHASE_BEFORE" != "$now" ]
	else
		echo "# no initrd phase in PCR 11: not a measured UKI boot" &&
		[ "$PHASE_BEFORE" = "$now" ]
	fi
'

test_expect_success 'the pins and the identity live under /run and survived the switch' '
	test -e /run/shirudo/bpffs/lsm_link &&
	test -e /run/shirudo/bpffs/identity &&
	grep -q " /run/shirudo/bpffs bpf " /proc/self/mounts
'

test_expect_success 'the runtime command can check initialization after switch-root' '
	"$SHIRUDO_BIN" init >/dev/null 2>&1 &&
	"$SHIRUDO_BIN" status --json >"$STATUS" 2>/dev/null &&
	[ "$(status_field tpm.bound_in)" = initrd ]
'

# The QEMU TPM suite enables just this syscall exit at boot. A successful
# service alone could also mean systemd used its move-mount fallback.
if grep -qw 'trace_event=syscalls:sys_exit_pivot_root' /proc/cmdline; then
	test_expect_success 'host PID 1 completed a native pivot_root' '
		grep -E -- "-1[[:space:]]+\[.*(sys_exit_pivot_root:|sys_pivot_root ->) (0x)?0+([[:space:]]|$)" /sys/kernel/tracing/trace ||
		{ grep -i pivot /sys/kernel/tracing/trace; false; }
	'

	test_expect_success 'systemd restored shared propagation with no mount refusal' '
		[ "$(status_field tamper_attempts.counters.BpffsMount)" = 0 ] &&
		[ "$(status_field tamper_attempts.counters.BpffsUmountAbove)" = 0 ] &&
		for path in / /run /run/shirudo /run/shirudo/bpffs; do
			findmnt -n -o PROPAGATION -T "$path" | grep -qw shared || return 1
		done
	'
fi

test_done
