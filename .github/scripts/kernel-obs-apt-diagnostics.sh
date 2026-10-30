#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -u

echo 'apt install failed; collecting package and initramfs diagnostics' >&2
dpkg --audit || true
ls -la /boot /lib/modules || true

for modules in /lib/modules/*; do
	[ -d "$modules" ] || continue
	kernel=${modules##*/}
	if [ -e "/boot/initrd.img-$kernel" ]; then
		update-initramfs -u -k "$kernel" || true
	else
		update-initramfs -c -k "$kernel" || true
	fi
done

tail -n 100 /var/log/dpkg.log || true
tail -n 100 /var/log/apt/term.log || true
