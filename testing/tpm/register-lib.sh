#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

[ "${SHIRUDO_TEST_REGISTER_VM:-0}" = 1 ] ||
	test_skip_all "run with make -C testing test-tgt-register (real kernel signer required)"
[ "$(id -u)" = 0 ] && [ -x "$R" ] || {
	echo "register VM requires root and the built register helper" >&2
	exit 1
}
[ ! -e /run/shirudo/bpffs/identity ] && [ ! -e /run/shirudo/bpffs/lsm_link ] || {
	echo "register protocol tests must run before shirudo init" >&2
	exit 1
}

WRITER_CREATED=0
MOUNTED=0

register_writer_start() {
	mkdir -p /run/shirudo/bpffs
	if mountpoint -q /run/shirudo/bpffs; then
		echo "register protocol tests require an unused private bpffs" >&2
		return 1
	fi
	mount -t bpf -o nosuid,nodev,noexec bpf /run/shirudo/bpffs || return 1
	MOUNTED=1
	"$R" writer-create || return 1
	WRITER_CREATED=1
}

register_writer_stop() {
	writer_result=0
	if [ "$WRITER_CREATED" = 1 ]; then
		"$R" writer-remove || writer_result=1
	fi
	if [ "$MOUNTED" = 1 ]; then
		umount /run/shirudo/bpffs || writer_result=1
	fi
	return "$writer_result"
}
