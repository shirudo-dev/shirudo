#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail
chmod 0755 /usr/local/bin/shirudo /usr/local/bin/shirudo-runtime \
	/usr/local/bin/shirudo-gen-initrd \
	/usr/lib/dracut/modules.d/90shirudo/module-setup.sh
mkdir -p /root/prototype-backup
if [ -d /var/lib/shirudo/upatches ] && [ ! -e /root/prototype-backup/upatches ]; then
	mv /var/lib/shirudo/upatches /root/prototype-backup/upatches
fi
mkdir -p /var/lib/shirudo/upatches
/usr/local/bin/shirudo-gen-initrd --kver "$1" --output /boot/initrd-shirudo-verity.img \
	--binary /usr/local/bin/shirudo --binary-path /usr/local/bin/shirudo \
	--cert /var/lib/shirudo/keys/cert.der --bootstrap-conf /etc/shirudo/shirudo.conf \
	--unit /usr/lib/systemd/system/shirudo-initrd.service \
	-- --no-hostonly --no-hostonly-cmdline --add-drivers 'efivarfs dm_mod dm_verity loop ext4' \
	--modules 'base systemd systemd-initrd dracut-systemd rootfs-block fs-lib udev-rules terminfo shirudo' \
	>/root/test-results/verity/initrd-build.log 2>&1
ukify build --linux /boot/vmlinuz-shirudo-verity --initrd /boot/initrd-shirudo-verity.img \
	--cmdline @/etc/kernel/cmdline --os-release @/etc/os-release \
	--output /boot/shirudo-verity.efi >/root/test-results/verity/uki-build.log 2>&1
