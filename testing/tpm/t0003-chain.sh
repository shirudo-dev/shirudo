#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0003 -- util/chain pure helpers: sha256, hex encode/decode bounds
# and constant-time compare. These underpin the measurement register;
# a drift here silently breaks attestation.

cd "$(dirname "$0")/.."
. ./test-lib.sh

H=helper/test-chain

test_expect_success 'sha256("abc") matches the known FIPS-180 vector' '
	[ "$(./$H sha256 abc)" = \
	  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]
'

test_expect_success 'hex_decode accepts exact length, lower and upper case' '
	./$H decode 0aFf 2 | grep -qx "rc=0" &&
	[ "$(./$H decode DEadBE 3 | tail -1)" = "deadbe" ]
'

test_expect_success 'hex_decode rejects wrong length -> EINVAL' '
	./$H decode abc 1 | grep -qx "rc=-22" &&
	./$H decode abcd 1 | grep -qx "rc=-22"
'

test_expect_success 'hex_decode rejects non-hex chars -> EINVAL' '
	./$H decode zz 1 | grep -qx "rc=-22"
'

test_expect_success 'ct_eq: equal buffers -> 1, one-bit diff -> 0' '
	[ "$(./$H cteq 00ff 00ff)" = "1" ] &&
	[ "$(./$H cteq 00ff 01ff)" = "0" ]
'

test_done
