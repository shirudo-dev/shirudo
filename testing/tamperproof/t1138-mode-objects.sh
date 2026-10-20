#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

mode_pins() {
	for pin in devices config_roots file_ioctl_link \
		bdev_integrity_link bdev_free_link seal_mmap_link seal_mprotect_link; do
		case "${SHIRUDO_TEST_MODE:-legacy}" in
		verity) [ -e "/run/shirudo/bpffs/$pin" ] || return 1 ;;
		legacy) [ ! -e "/run/shirudo/bpffs/$pin" ] || return 1 ;;
		*) return 1 ;;
		esac
	done
}

test_expect_success 'only image mode pins image device and executable guards' '
	mode_pins
'

test_done
