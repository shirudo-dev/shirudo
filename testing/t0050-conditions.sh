#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0050 -- util/conditions.c: the KeyringSealed condition names the kind
# of keyring the anchor is in, a keyring other than the one init froze,
# or none where it froze one, makes the status tampered, and the register
# conditions tell a TPM that does not answer from one with no register.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-conditions

test_expect_success 'the bpf keyring init froze is the production anchor' '
	out=$(./$H 1 bpf 100 100 match) &&
	echo "$out" | grep -qx "status=ok" &&
	echo "$out" | grep -qx "KeyringSealed OK serial=100 in the BPF keyring, pin matches"
'

test_expect_success 'before init the keyring is pending, not tampered' '
	out=$(./$H 0 none -1 0 none) &&
	echo "$out" | grep -qx "status=lsm-off" &&
	echo "$out" | grep -qx "KeyringSealed WARN shirudo keyring absent (not init'"'"'d?)"
'

test_expect_success 'a swapped keyring is tampered' '
	out=$(./$H 1 bpf 101 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "reason=keyring serial swap detected" &&
	echo "$out" | grep -qx "KeyringSealed ALERT pin serial=100 != live serial=101 (swapped?)"
'

test_expect_success 'a frozen bpf keyring that is gone is tampered' '
	out=$(./$H 1 bpf -1 100 match) &&
	echo "$out" | grep -qx "status=tampered" &&
	echo "$out" | grep -qx "KeyringSealed ALERT pin serial=100, the BPF keyring is gone (removed?)"
'

test_expect_success 'with the LSM off a gone keyring is still tampered' '
	./$H 0 bpf -1 200 none | grep -qx "status=tampered"
'

test_expect_success 'a register mismatch is the reason given first' '
	./$H 1 bpf -1 200 mismatch |
		grep -qx "reason=live register != eventlog replay"
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

test_done
