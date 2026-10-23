#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0035 -- the record an init run from the initrd leaves under /run:
# readers see it as this boot's init record before the root file
# system's init adopts it, and adoption appends it to the eventlog
# exactly once.

cd "$(dirname "$0")/.."
. ./test-lib.sh
H=helper/test-eventlog
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export SHIRUDO_EVENTLOG_PATH="$W/eventlog"
export SHIRUDO_EVENTLOG_PENDING_PATH="$W/eventlog.pending"

test_expect_success 'no log and no pending record: no init this boot' '
	./$H boot-init | grep -qx "rc=-2"
'

test_expect_success 'a pending record is this boot'"'"'s init record' '
	./$H init pending initrd | grep -qx "rc=0" &&
	test ! -e "$SHIRUDO_EVENTLOG_PATH" &&
	./$H boot-init | grep -qx "bound_in=initrd" &&
	./$H lines | grep -qx "lines=1"
'

test_expect_success 'adoption appends it to the log and removes the pending file' '
	cp "$SHIRUDO_EVENTLOG_PENDING_PATH" "$W/saved" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ] &&
	./$H boot-init | grep -qx "bound_in=initrd"
'

test_expect_success 'adopting the same record again changes nothing' '
	cp "$W/saved" "$SHIRUDO_EVENTLOG_PENDING_PATH" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ] &&
	./$H adopt | grep -qx "rc=0" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 1 ]
'

test_expect_success 'a pending record follows the log'"'"'s records of this boot' '
	./$H init pending initrd 2 | grep -qx "rc=0" &&
	./$H boot-init | grep -qx "reset_count=2" &&
	./$H lines | grep -qx "lines=2" &&
	./$H adopt | grep -qx "pending=absent" &&
	[ "$(wc -l < "$SHIRUDO_EVENTLOG_PATH")" = 2 ] &&
	./$H boot-init | grep -qx "records=2"
'

test_done
