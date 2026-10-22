#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

test_expect_success 'device, memory and config-root guards are pinned' '
	for pin in devices config_roots file_ioctl_link bdev_integrity_link \
		bdev_free_link seal_mmap_link seal_mprotect_link; do
		[ -e "/run/shirudo/bpffs/$pin" ] || return 1
	done
'

test_done
