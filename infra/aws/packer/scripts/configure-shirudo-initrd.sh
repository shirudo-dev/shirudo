#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

kernel_release="$(cat /etc/bpf-next-kernel-release)"
if [[ "$(uname -r)" != "$kernel_release" ]]; then
  echo "Running kernel $(uname -r) does not match ${kernel_release}" >&2
  exit 1
fi

if ! grep -q -w 'bpf.keyring_unsealed=1' /proc/cmdline; then
  echo "Running kernel command line lacks bpf.keyring_unsealed=1" >&2
  exit 1
fi
if ! grep -q -w 'dm_verity.keyring_unsealed=1' /proc/cmdline; then
  echo "Running kernel command line lacks dm_verity.keyring_unsealed=1" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get install -y dracut systemd-boot-efi systemd-ukify

command -v dracut >/dev/null
command -v shirudo-gen-initrd >/dev/null
command -v ukify >/dev/null

assets_dir="$(mktemp -d)"
trap 'rm -rf "$assets_dir"' EXIT
sudo tar -xzf /tmp/shirudo-image-assets.tar.gz -C "$assets_dir"
for file in \
  shirudo-target \
  initial.img initial.verity initial.roothash initial.p7s \
  runtime.img runtime.verity runtime.roothash runtime.p7s \
  runtime-service.conf initrd-bootstrap.conf; do
  if [[ ! -s "$assets_dir/$file" ]]; then
    echo "Missing Shirudo image asset: $file" >&2
    exit 1
  fi
done
if [[ ! -x "$assets_dir/shirudo-target" ]]; then
  echo "Branch-built shirudo-target is not executable" >&2
  exit 1
fi

runtime_root_hash="$(cat "$assets_dir/runtime.roothash")"
if ! grep -Fxq "runtime.root_hash = $runtime_root_hash" \
  "$assets_dir/initrd-bootstrap.conf"; then
  echo "Initrd bootstrap root hash does not match runtime.roothash" >&2
  exit 1
fi
if ! grep -Fxq 'runtime.image = /var/lib/shirudo/images/runtime' \
  "$assets_dir/initrd-bootstrap.conf"; then
  echo "Initrd bootstrap must name /var/lib/shirudo/images/runtime" >&2
  exit 1
fi

# shirudo rejects bootstrap settings writable by group or other users. The
# asset tarball may have been created under a permissive umask.
sudo chown root:root "$assets_dir/initrd-bootstrap.conf"
sudo chmod 0644 "$assets_dir/initrd-bootstrap.conf"

sudo install -d -o root -g root -m 0755 /var/lib/shirudo/images
for prefix in initial runtime; do
  for suffix in img verity roothash p7s; do
    sudo install -o root -g root -m 0644 \
      "$assets_dir/$prefix.$suffix" \
      "/var/lib/shirudo/images/$prefix.$suffix"
  done
done
sudo install -D -o root -g root -m 0644 \
  "$assets_dir/runtime-service.conf" \
  /etc/systemd/system/shirudo.service.d/verity.conf

for service in shirudo-keepalive shirudo-map-export \
  shirudo-bpm-repo-update shirudo-bpm-tree-sync; do
  sudo install -d -o root -g root -m 0755 \
    "/etc/systemd/system/${service}.service.d"
done
sudo tee /etc/systemd/system/shirudo-keepalive.service.d/runtime.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/run/shirudo/runtime/usr/bin/shirudo status --otel --include-system
EOF
sudo tee /etc/systemd/system/shirudo-map-export.service.d/runtime.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/run/shirudo/runtime/usr/bin/shirudo upatch map --all
EOF
sudo tee /etc/systemd/system/shirudo-bpm-repo-update.service.d/runtime.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=-/run/shirudo/runtime/usr/bin/shirudo bpm repo update
ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm upgrade
EOF
sudo tee /etc/systemd/system/shirudo-bpm-tree-sync.service.d/runtime.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm tree sync
EOF

tcti_device="$(ldconfig -p | awk '$1 == "libtss2-tcti-device.so.0" { print $NF; exit }')"
if [[ -z "$tcti_device" || ! -r "$tcti_device" ]]; then
  echo "libtss2-tcti-device.so.0 is required to initialize the TPM in the initrd" >&2
  exit 1
fi

sudo shirudo-gen-initrd --kver "$kernel_release" \
  --binary "$assets_dir/shirudo-target" \
  --binary-path /usr/bin/shirudo \
  --bootstrap-conf "$assets_dir/initrd-bootstrap.conf" \
  -- --no-hostonly --install "$tcti_device"
initrd="/boot/initrd.img-${kernel_release}"
sudo shirudo-gen-initrd --check "$initrd"
initrd_listing="$(sudo lsinitrd "$initrd")"
if ! grep -q -- 'libtss2-tcti-device\.so\.0' <<<"$initrd_listing"; then
  echo "libtss2-tcti-device.so.0 is missing from $initrd" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])etc/hostname([[:space:]]|$)' <<<"$initrd_listing"; then
  echo "Builder hostname must not be embedded in $initrd" >&2
  exit 1
fi
if grep -Eq '(^|[[:space:]])etc/machine-id([[:space:]]|$)' <<<"$initrd_listing"; then
  initrd_machine_id="$(sudo lsinitrd -f etc/machine-id "$initrd")"
  if [[ -n "$initrd_machine_id" && "$initrd_machine_id" != uninitialized ]]; then
    echo "Builder machine ID must not be embedded in $initrd" >&2
    exit 1
  fi
fi

esp="$(findmnt -n -o TARGET /boot/efi || true)"
if [[ "$esp" != "/boot/efi" ]]; then
  echo "Expected the EFI system partition mounted at /boot/efi" >&2
  exit 1
fi

esp_uuid="$(sudo grub-probe --target=fs_uuid /boot/efi)"
uki_dir="${esp}/EFI/Linux"
uki_path="${uki_dir}/shirudo-${kernel_release}.efi"
sudo install -d -o root -g root -m 0755 "$uki_dir"

kernel_cmdline="$(sed -E 's/(^|[[:space:]])BOOT_IMAGE=[^[:space:]]+//g; s/^[[:space:]]+//; s/[[:space:]]+$//' /proc/cmdline)"
for parameter in bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1; do
  case " $kernel_cmdline " in
    *" $parameter "*) ;;
    *) kernel_cmdline="$kernel_cmdline $parameter" ;;
  esac
done

sudo ukify build \
  --linux="/boot/vmlinuz-${kernel_release}" \
  --initrd="$initrd" \
  --cmdline="$kernel_cmdline" \
  --output="$uki_path"
sudo ukify inspect "$uki_path" >/dev/null

sudo tee /etc/grub.d/41_shirudo_uki >/dev/null <<EOF
#!/bin/sh
cat <<'GRUB_EOF'
menuentry 'Shirudo UKI (${kernel_release})' {
    insmod part_gpt
    insmod fat
    search --no-floppy --fs-uuid --set=root ${esp_uuid}
    chainloader /EFI/Linux/shirudo-${kernel_release}.efi
}
GRUB_EOF
EOF
sudo chmod 0755 /etc/grub.d/41_shirudo_uki
sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' \
  /etc/default/grub.d/99-bpf-next.cfg
if grep -q '^GRUB_SAVEDEFAULT=' /etc/default/grub.d/99-bpf-next.cfg; then
  sudo sed -i 's/^GRUB_SAVEDEFAULT=.*/GRUB_SAVEDEFAULT=true/' \
    /etc/default/grub.d/99-bpf-next.cfg
else
  echo 'GRUB_SAVEDEFAULT=true' | \
    sudo tee -a /etc/default/grub.d/99-bpf-next.cfg >/dev/null
fi
sudo update-grub
sudo grub-set-default "Shirudo UKI (${kernel_release})"
sudo update-grub

sudo ln -sf /run/shirudo/runtime/usr/bin/shirudo /usr/local/bin/shirudo

printf 'Shirudo UKI: %s\n' "$uki_path"
printf 'GRUB default: %s\n' "Shirudo UKI (${kernel_release})"
