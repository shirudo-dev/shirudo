#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

source_dir=$(cd "$(dirname "$0")/.." && pwd)
templates="$source_dir/contrib/verity-vm"
state=${SHIRUDO_VERITY_VM_STATE:-$HOME/.linux-kernel-vscode/shirudo-verity}
kernel=
keys_dir=
probes=()
while [ $# -gt 0 ]; do
	case "$1" in
	--kernel) kernel=${2:?}; shift 2 ;;
	--keys-dir) keys_dir=${2:?}; shift 2 ;;
	--probe) probes+=("${2:?}"); shift 2 ;;
	*) printf 'usage: %s --kernel <built-kernel-tree> --keys-dir <operator-keys> [--probe <trusted-ELF>]\n' "$0" >&2; exit 2 ;;
	esac
done
[ -n "$kernel" ] && [ -n "$keys_dir" ] || exit 2
[ -f "$kernel/arch/x86/boot/bzImage" ] && [ -f "$kernel/include/config/kernel.release" ] || exit 1
[ -x "$source_dir/shirudo-target" ] && [ -x "$source_dir/tools/shirudo-build/shirudo-build" ] || exit 1
vm="$source_dir/contrib/verity-vm.sh"
"$vm" ssh 'test ! -e /run/shirudo/bpffs/lsm_link && test -w /var/lib/shirudo'
mkdir -p "$state/fixtures"
work=$(mktemp -d "$state/fixtures/build.XXXXXX")
install -m 0755 "$source_dir/shirudo-target" "$work/shirudo-target"
release=$(cat "$kernel/include/config/kernel.release")

for name in config-a config-b config-bad; do
	mkdir -p "$work/$name/etc/shirudo" "$work/$name/keys/trusted" "$work/$name/keys/revoked"
	sed "s/@tenant@/$name/g" "$templates/config.conf.in" \
		>"$work/$name/etc/shirudo/shirudo.conf"
	if [ "$name" = config-bad ]; then
		printf 'invalid certificate\n' >"$work/$name/keys/revoked/0000000000000000000000000000000000000000000000000000000000000000.der"
	fi
	"$source_dir/tools/gen-image/shirudo-gen-image" --source "$work/$name" \
		--output "$work/$name" --keys-dir "$keys_dir" --size 8 \
		--builder "$source_dir/tools/shirudo-build/shirudo-build"
done
sed 's/@config_image@/config-a/g' "$templates/runtime.conf.in" \
	>"$work/runtime.conf"
extra=()
for probe in "${probes[@]}"; do
	extra+=(--extra-binary "$probe")
done
"$source_dir/tools/gen-image/shirudo-gen-runtime" --binary "$work/shirudo-target" \
	--bootstrap-conf "$work/runtime.conf" --cert "$keys_dir/cert.der" \
	--config-cert "$keys_dir/cert.der" --output "$work/runtime" \
	--keys-dir "$keys_dir" --builder "$source_dir/tools/shirudo-build/shirudo-build" \
	--unit-output "$work/runtime-service.conf" "${extra[@]}" >"$work/runtime-root"
runtime_command=$(sed -n 's/^ExecStart=\(.*\) init$/\1/p' "$work/runtime-service.conf")
[ -n "$runtime_command" ]
command_escaped=$(printf '%s' "$runtime_command" | sed 's/[\&|]/\\&/g')
sed "s|@runtime_command@|$command_escaped|g" "$templates/shirudo-runtime.in" \
	>"$work/shirudo-runtime"
sed "s/@root_hash@/$(cat "$work/runtime-root")/g" \
	"$templates/bootstrap.conf.in" >"$work/bootstrap.conf"

make -C "$kernel" -j"$(nproc)" LLVM=1 INSTALL_MOD_STRIP=1 INSTALL_MOD_PATH="$work/modules" modules_install

tar -C "$work/modules" -cf - "lib/modules/$release" | "$vm" ssh tar -xf - -C /
"$vm" push "$kernel/arch/x86/boot/bzImage" /boot/vmlinuz-shirudo-verity
"$vm" push "$work/shirudo-target" /usr/local/bin/shirudo
"$vm" push "$work/shirudo-runtime" /usr/local/bin/shirudo-runtime
"$vm" ssh 'mkdir -p /var/lib/shirudo/images /etc/shirudo /usr/lib/dracut/modules.d/90shirudo /etc/systemd/system/shirudo.service.d /root/test-results/verity'
for name in config-a config-b config-bad runtime; do
	for suffix in img verity roothash p7s; do
		"$vm" push "$work/$name.$suffix" "/var/lib/shirudo/images/$name.$suffix"
	done
done
"$vm" push "$work/bootstrap.conf" /etc/shirudo/shirudo.conf
"$vm" push "$work/runtime-service.conf" /etc/systemd/system/shirudo.service.d/verity.conf
"$vm" push "$source_dir/tools/gen-initrd/module-setup.sh" /usr/lib/dracut/modules.d/90shirudo/module-setup.sh
"$vm" push "$source_dir/tools/gen-initrd/shirudo-gen-initrd" /usr/local/bin/shirudo-gen-initrd
"$vm" push "$keys_dir/cert.der" /var/lib/shirudo/keys/cert.der
sed 's|@bindir@|/usr/local/bin|g' "$source_dir/systemd/shirudo-initrd.service.in" >"$work/shirudo-initrd.service"
"$vm" push "$work/shirudo-initrd.service" /usr/lib/systemd/system/shirudo-initrd.service

"$vm" push "$templates/kernel.cmdline" /etc/kernel/cmdline
"$vm" ssh bash -s -- "$release" <"$templates/install-guest.sh"
"$vm" pull /boot/shirudo-verity.efi "$state/shirudo-verity.efi"
"$vm" pull /boot/initrd-shirudo-verity.img "$state/initrd-verity.img"
image_file=$(mktemp "$state/esp.img.XXXXXX")
trap 'rm -f "$image_file"' EXIT
truncate -s 256M "$image_file"
sfdisk "$image_file" <"$templates/esp.sfdisk" >/dev/null
mformat -i "$image_file@@1048576" -F -v SHIRUDOV ::
mmd -i "$image_file@@1048576" ::/EFI ::/EFI/BOOT
mcopy -i "$image_file@@1048576" "$state/shirudo-verity.efi" ::/EFI/BOOT/BOOTX64.EFI
if [ ! -e "$state/esp.legacy.img" ]; then
	cp --reflink=auto --sparse=always "$state/esp.img" "$state/esp.legacy.img"
fi
mv "$image_file" "$state/esp.img"
trap - EXIT
touch "$state/verity-ready"
printf 'Fixtures: %s\nPrototype UKI ready. Stop the installation VM, then start the prototype VM.\n' "$work"
