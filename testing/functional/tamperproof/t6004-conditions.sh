#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6004 -- util/conditions.c: the KeyringSealed condition covers the bpf
# and dm-verity keyrings init froze; a keyring other than the one init
# froze, none where it froze one, a link init did not freeze or a config
# key that is gone makes the status tampered, and the register
# conditions tell a TPM that does not answer from one with no register.
# A pending config activation is reboot-pending, and a config its records
# cannot vouch for is tampered. A pin without a record of this boot is
# tampered, and pins that cannot be checked are a warning.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=helper/test-conditions

test_expect_success 'the bpf keyring init froze is the production anchor' '
	out=$(./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=ok" &&
	echo "$out" | grep -qx "KeyringSealed OK bpf serial 100, dm-verity serial 200, pins match"
'

test_expect_success 'before init the keyring is pending, not tampered' '
	out=$(./$H 0 none -1 0 none) &&
	echo "$out" | grep -qx "status=lsm-off" &&
	echo "$out" | grep -qx "KeyringSealed WARN .bpf keyring absent before init"
'

test_expect_success 'a swapped keyring is tampered' '
	out=$(./$H 1 bpf 101 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=keyring serial swap detected" &&
	echo "$out" | grep -qx "KeyringSealed ALERT pinned serial 100, live serial 101: swapped"
'

test_expect_success 'a frozen bpf keyring that is gone is tampered' '
	out=$(./$H 1 bpf -1 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "KeyringSealed ALERT pinned serial 100, the .bpf keyring is gone"
'

test_expect_success 'a swapped dm-verity keyring is tampered' '
	out=$(SHIRUDO_TEST_DMV_SERIAL=201 ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=dm-verity keyring serial swap detected" &&
	echo "$out" | grep -qx "KeyringSealed ALERT dm-verity pinned serial 200, live serial 201: swapped"
'

test_expect_success 'a frozen dm-verity keyring that is gone is tampered' '
	out=$(SHIRUDO_TEST_DMV_SERIAL=-1 ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=the dm-verity keyring init froze is gone" &&
	echo "$out" | grep -qx "KeyringSealed ALERT dm-verity pinned serial 200, the dm-verity keyring is gone"
'

test_expect_success 'a link init did not freeze is tampered, in either keyring' '
	out=$(SHIRUDO_TEST_BPF_UNFROZEN=1 ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=a keyring holds a link init did not freeze" &&
	echo "$out" | grep -qx "KeyringSealed ALERT the BPF keyring holds 1 link init did not freeze" &&
	out=$(SHIRUDO_TEST_DMV_UNFROZEN=2 ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "KeyringSealed ALERT the dm-verity keyring holds 2 links init did not freeze"
'

test_expect_success 'a config key that is gone is tampered' '
	out=$(SHIRUDO_TEST_DMV_KEY=missing ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=the config key init froze is gone" &&
	echo "$out" | grep -qx "KeyringSealed ALERT a config key init froze is gone from the dm-verity keyring"
'

test_expect_success 'a bpf keyring swap is reported before the dm-verity state' '
	SHIRUDO_TEST_DMV_SERIAL=201 ./$H 1 bpf 101 100 match |
		grep -qx "KeyringSealed ALERT pinned serial 100, live serial 101: swapped"
'

test_expect_success 'with the LSM off a gone keyring is still tampered' '
	./$H 0 bpf -1 200 none | grep -qx "status=tampered"
'

test_expect_success 'a register mismatch is the reason given first' '
	./$H 1 bpf -1 200 mismatch |
		grep -qx "reason=live register differs from the eventlog replay"
'

test_expect_success 'no TPM answering is told apart from an unbound register' '
	out=$(./$H 1 bpf 100 100 notpm) &&
	echo "$out" | grep -qx "status=degraded" &&
	echo "$out" | grep -qx "reason=no TPM answered" &&
	echo "$out" | grep -qx "ChainIntact WARN no TPM answered, no register to replay" &&
	echo "$out" | grep -qx "TpmMeasured WARN no TPM answered"
'

test_expect_success 'a TPM without a register this boot says so' '
	out=$(./$H 1 bpf 100 100 none) &&
	echo "$out" | grep -qx "status=degraded" &&
	echo "$out" | grep -qx "reason=no register bound this boot" &&
	echo "$out" | grep -qx "ChainIntact WARN no register bound this boot (init incomplete)" &&
	echo "$out" | grep -qx "TpmMeasured WARN NV index 0x01818E00 not bound this boot"
'

test_expect_success 'a bound register is measured' '
	./$H 1 bpf 100 100 match |
		grep -qx "TpmMeasured OK NV index 0x01818E00 readable"
'

test_expect_success 'every pinned upatch in the records is OK' '
	./$H 1 bpf 100 100 match |
		grep -qx "UpatchesMeasured OK every pinned or archived upatch is in this boot.s records"
'

test_expect_success 'a pin without a record of this boot is tampered' '
	out=$(SHIRUDO_TEST_PINS=unmeasured:shirudo-test-basic,kernel-obs ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=a upatch is pinned or archived without a record of this boot" &&
	echo "$out" | grep -qx "UpatchesMeasured ALERT 2 pinned or archived without a record of this boot: shirudo-test-basic,kernel-obs"
'

test_expect_success 'pins that cannot be checked are a warning, not a verdict' '
	out=$(SHIRUDO_TEST_PINS=norecord ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=ok" &&
	echo "$out" | grep -qx "UpatchesMeasured WARN no record of this boot to check the pins against" &&
	out=$(SHIRUDO_TEST_PINS=error ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=ok" &&
	echo "$out" | grep -qx "UpatchesMeasured WARN pins not checked against the records: Permission denied"
'

test_expect_success 'a register mismatch is the reason given before the pins' '
	SHIRUDO_TEST_PINS=unmeasured:x ./$H 1 bpf 100 100 mismatch |
		grep -qx "reason=live register differs from the eventlog replay"
'

test_expect_success 'an active config is OK' '
	./$H 1 bpf 100 100 match |
		grep -qx "ConfigActive OK config 0123456789ab.. is active"
'

test_expect_success 'a pending activation is reboot-pending' '
	out=$(SHIRUDO_TEST_CONFIG_STATE=pending ./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=reboot-pending" &&
	echo "$out" | grep -qx "reason=a config activation is pending until the next reboot" &&
	echo "$out" | grep -qx "ConfigActive WARN the activation of config 0123456789ab.. is pending until the next reboot"
'

test_expect_success 'a config its records cannot vouch for is tampered' '
	for state in untrusted stale
	do
		out=$(SHIRUDO_TEST_CONFIG_STATE=$state ./$H 1 bpf 100 100 match) &&
		echo "$out" | grep -qx "status=tampered" &&
		echo "$out" | grep -qx "reason=the selected config cannot be verified against its records" &&
		echo "$out" | grep -q "^ConfigActive ALERT " || return 1
	done
'

test_expect_success 'a pending activation does not hide a register mismatch' '
	SHIRUDO_TEST_CONFIG_STATE=pending ./$H 1 bpf 100 100 mismatch |
		grep -qx "status=tampered"
'

test_done
