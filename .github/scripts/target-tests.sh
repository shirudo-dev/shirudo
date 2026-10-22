#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/target-tests.sh -- run the target suite in the test VM as
# make -C testing test-tgt does on a developer's host. setup makes the
# runner the VM host: KVM, the VM's packages, the bpf-next kernel unless a
# restored copy is current, and the OpenSSL 3.5 toolchain from
# vm-toolchain.sh. The suite boots an image-backed target from a dracut initrd.
#
#   .github/scripts/target-tests.sh setup|production
#
# Runs as a user with passwordless sudo, from the checkout.

set -eu

cd "$(git rev-parse --show-toplevel)"

kernel=artifacts/bpf-next-kernel-debs

# What the job log alone does not show: refusals by AppArmor, the passt
# helper libguestfs networks its appliance through, and, for each guest
# that did not pass, what it and the suites in it printed.
diagnose() {
	echo '::group::Diagnostics'
	sudo dmesg | grep 'apparmor="DENIED"' | tail -n 20 || :
	sudo journalctl -b --no-pager -t passt | tail -n 20 || :
	for vm in build/test-vm/vms/*; do
		[ "$(cat "$vm/result/status" 2>/dev/null)" != 0 ] || continue
		for log in "$vm/result/guest.log" "$vm/console.log"; do
			[ -f "$log" ] || continue
			echo "== $log"
			cat "$log"
		done
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

setup() {
	sudo rm -rf /opt/ghc /usr/local/lib/android /usr/share/dotnet

	# /dev/kvm belongs to root on the runner.
	echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
		sudo tee /etc/udev/rules.d/99-kvm.rules >/dev/null
	sudo udevadm control --reload-rules
	sudo udevadm trigger --name-match=kvm

	# A restored kernel is older than the checkout of the script that
	# built it.
	if [ -s "$kernel/bzImage.sha256sum" ]; then
		touch "$kernel/bzImage.sha256sum"
	fi
	make -C testing kernel

	mkdir -p build
	sudo BPF_VMLINUX_BTF="$PWD/$kernel/vmlinux.btf" \
		.github/scripts/vm-toolchain.sh \
		autoconf autoconf-archive automake clang-20 cloud-image-utils \
		dracut-core file isc-dhcp-client libguestfs-tools libltdl-dev \
		libtool libzstd-dev cryptsetup-bin e2fsprogs qemu-system-x86 qemu-utils swtpm \
		swtpm-tools tpm2-tools

	# Ubuntu 24.04's clang 18 lacks the BPF address-space casts the
	# arena upatches need, and shirudo-build runs /usr/bin/clang.
	sudo ln -sf clang-20 /usr/bin/clang

	# Ubuntu's dracut 060 looks for systemd-pcrphase, which systemd 255
	# calls systemd-pcrextend, and so leaves out the PCR phase
	# measurement shirudo's initrd needs.
	if [ ! -e /usr/lib/systemd/systemd-pcrphase ]; then
		sudo ln -s systemd-pcrextend /usr/lib/systemd/systemd-pcrphase
	fi

	# libguestfs networks the appliance through passt. Ubuntu's AppArmor
	# profile for passt refuses the socket libguestfs asks for under
	# XDG_RUNTIME_DIR, and without that profile Ubuntu's restriction of
	# unprivileged user namespaces keeps passt from sandboxing itself.
	# The runner is discarded after the job, so lift both.
	apparmor=/sys/kernel/security/apparmor
	if sudo grep -q '^passt ' "$apparmor/profiles" 2>/dev/null; then
		printf passt | sudo tee "$apparmor/.remove" >/dev/null
	fi
	if [ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]; then
		sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
	fi
}

case "${1:-}" in
setup|production) ;;
*)
	echo "usage: $0 setup|production" >&2
	exit 2
	;;
esac

trap finish EXIT

if [ "$1" = setup ]; then
	setup
	exit 0
fi

# shellcheck source=/dev/null
. build/vm-toolchain.env

# A guest that boots runs the suite in minutes; one that hangs, in
# emergency mode for instance, would otherwise hold the job for an hour.
export TEST_VM_TIMEOUT=900

sudo -E env PATH="$PATH" make -C testing test-tgt
