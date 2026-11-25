#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

traps='kvm-arm.vgic_v3_group0_trap=1 kvm-arm.vgic_v3_group1_trap=1 kvm-arm.vgic_v3_common_trap=1'
cfg=/etc/default/grub.d/90-shirudo-kvm.cfg

line='GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT '"$traps"'"'
if [ "$(cat "$cfg" 2>/dev/null)" != "$line" ] ||
   ! grep -qF -- "$traps" /boot/grub/grub.cfg; then
	command -v update-grub >/dev/null
	printf '%s\n' "$line" >"$cfg"
	update-grub
fi

cmdline=$(cat /proc/cmdline)
for flag in $traps; do
	case " $cmdline " in
	*" $flag "*) ;;
	*)
		echo "Restart the Lima VM to boot with the GICv3 traps."
		break
		;;
	esac
done
