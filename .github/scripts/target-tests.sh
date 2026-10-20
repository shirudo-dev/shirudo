#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/target-tests.sh -- run the target suite in the test VM as
# make -C testing test-tgt does on a developer's host, in the staging
# configuration and then booted from a dracut initrd in the production
# one. The runner is the VM host: it gets KVM, the VM's packages, the
# bpf-next kernel unless a restored copy is current, and the OpenSSL 3.5
# toolchain from vm-toolchain.sh.
#
#   .github/scripts/target-tests.sh
#
# Runs as a user with passwordless sudo, from the checkout.

set -eu

cd "$(git rev-parse --show-toplevel)"

kernel=artifacts/bpf-next-kernel-debs

# What the job log alone does not show: refusals by AppArmor, the passt
# helper libguestfs networks its appliance through, and the guests.
diagnose() {
	echo '::group::Diagnostics'
	sudo dmesg | grep 'apparmor="DENIED"' | tail -n 20 || :
	sudo journalctl -b --no-pager -t passt | tail -n 20 || :
	for log in build/test-vm/vms/*/console.log; do
		[ -f "$log" ] || continue
		echo "== $log"
		tail -n 60 "$log"
	done
	echo '::endgroup::'
}

# The production run leaves root's files behind; the caches need them.
finish() {
	status=$?
	sudo chown -R "$(id -u):$(id -g)" artifacts build 2>/dev/null || :
	[ "$status" -eq 0 ] || diagnose
	exit "$status"
}
trap finish EXIT

sudo rm -rf /opt/ghc /usr/local/lib/android /usr/share/dotnet

# /dev/kvm belongs to root on the runner.
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
	sudo tee /etc/udev/rules.d/99-kvm.rules >/dev/null
sudo udevadm control --reload-rules
sudo udevadm trigger --name-match=kvm

# A restored kernel is older than the checkout of the script that built it.
if [ -s "$kernel/bzImage.sha256sum" ]; then
	touch "$kernel/bzImage.sha256sum"
fi
make -C testing kernel

mkdir -p build
sudo BPF_VMLINUX_BTF="$PWD/$kernel/vmlinux.btf" .github/scripts/vm-toolchain.sh \
	autoconf autoconf-archive automake libtool libzstd-dev \
	cloud-image-utils dracut-core file libguestfs-tools qemu-system-x86 \
	qemu-utils swtpm swtpm-tools
# shellcheck source=/dev/null
. build/vm-toolchain.env

# libguestfs networks the appliance through passt, whose AppArmor profile
# refuses the socket libguestfs asks for under XDG_RUNTIME_DIR. The runner
# is discarded after the job, so lift the confinement.
if sudo grep -q '^passt ' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
	printf passt | sudo tee /sys/kernel/security/apparmor/.remove >/dev/null
fi

make -C testing test-tgt
sudo -E env PATH="$PATH" make -C testing test-tgt TEST_VM_INITRD=1
