#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/tests.sh -- run every test as make tests does on a
# developer's host. setup makes the runner the VM host: KVM, the VM's
# packages, the kernel CI artifact, and
# the OpenSSL 3.5 toolchain from vm-toolchain.sh. run builds and runs the
# unit, ci-checks, functional and end2end tests, each family of target tests
# in a VM of its own, or one part of them: unit runs the unit and
# ci-checks tests, functional and end2end the tier of that name.
# With VM=0, setup installs only host test dependencies using the kernel
# CI artifact's BTF, and run leaves out target VMs. CI supplies this artifact
# from github.com/shirudo-dev/kernel.
#
#   .github/scripts/tests.sh setup|run [unit|functional|end2end]
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

restore_workspace_ownership() {
	sudo chown -R "$(id -u):$(id -g)" .
}

# Setup and production runs leave root's files behind.
finish() {
	status=$?
	restore_workspace_ownership || status=$?
	[ "$status" -eq 0 ] || [ "${VM:-1}" = 0 ] || diagnose
	exit "$status"
}

# The kernel CI build carries the LSM hooks the programs of bpf/ attach to.
# A kernel built without one passes every other check and then fails init.
require_lsm_hooks() {
	btf="$1"
	names=$(mktemp) || return 1
	tr '\0' '\n' <"$btf" >"$names"
	missing=$(sed -nE 's/^SEC\("lsm(\.s)?\/([a-z0-9_]+)"\).*/\2/p' bpf/*.c |
		sort -u | while read -r hook; do
			grep -qx "bpf_lsm_$hook" "$names" || printf ' %s' "$hook"
		done)
	rm -f "$names"
	[ -z "$missing" ] && return 0
	printf 'kernel BTF lacks the LSM hooks%s: use a shirudo-dev/kernel build\n' \
		"$missing" >&2
	return 1
}

validate_kernel_install() {
	source_dir="$1"
	[ -d "$source_dir/boot" ] || {
		echo "kernel artifacts are missing: $source_dir/boot" >&2
		return 1
	}

	set -- "$source_dir"/boot/vmlinuz-*
	[ "$#" -eq 1 ] && [ -s "$1" ] || {
		echo "expected one kernel image in $source_dir/boot" >&2
		return 1
	}
	image="$1"
	release=${image##*/vmlinuz-}
	btf="$source_dir/boot/btf-$release"
	config="$source_dir/boot/config-$release"
	modules="$source_dir/lib/modules/$release"

	[ -s "$btf" ] || {
		echo "kernel BTF is missing: $btf" >&2
		return 1
	}
	[ -s "$config" ] || {
		echo "kernel config is missing: $config" >&2
		return 1
	}
	[ -d "$modules" ] || {
		echo "kernel modules are missing: $modules" >&2
		return 1
	}
	grep -aq 'signature_size' "$btf" || {
		echo "kernel BTF lacks bpf_attr.signature_size" >&2
		return 1
	}
	require_lsm_hooks "$btf" || return 1

	return 0
}

stage_kernel_install() {
	rm -rf "$kernel/lib/modules" || return 1
	mkdir -p "$kernel/lib/modules" || return 1
	cp "$image" "$kernel/bzImage" || return 1
	cp "$btf" "$kernel/vmlinux.btf" || return 1
	cp "$config" "$kernel/kernel.config" || return 1
	cp -a "$modules" "$kernel/lib/modules/" || return 1
	(
		cd "$kernel" || exit 1
		sha256sum bzImage > bzImage.sha256sum || exit 1
		sha256sum vmlinux.btf > vmlinux.btf.sha256sum || exit 1
	) || return 1
}

stage_kernel_ci_artifact() {
	artifact_dir="$1"
	set -- "$artifact_dir"/*/linux-image-*_amd64.deb
	[ "$#" -eq 1 ] && [ -s "$1" ] || {
		echo "expected one x86-64 kernel image package in $artifact_dir" >&2
		return 1
	}
	image_package="$1"
	package_dir=${image_package%/*}
	release=${image_package##*/linux-image-}
	release=${release%%_*}
	btf="$package_dir/vmlinux-$release.btf"
	[ -s "$btf" ] || {
		echo "kernel CI artifact lacks BTF for $release" >&2
		return 1
	}
	mkdir -p "$kernel" || return 1
	cp "$btf" "$kernel/vmlinux.btf" || return 1
	[ "${VM:-1}" != 0 ] || return 0

	set -- "$package_dir"/linux-headers-"$release"_*_amd64.deb
	[ "$#" -eq 1 ] && [ -s "$1" ] || {
		echo "expected headers package for kernel $release in $package_dir" >&2
		return 1
	}
	config="$package_dir/config-$release"
	[ -s "$config" ] || {
		echo "kernel CI artifact lacks config for $release" >&2
		return 1
	}
	install_root="$PWD/build/kernel-ci-extract"
	rm -rf "$install_root"
	mkdir -p "$install_root" || return 1
	dpkg-deb -x "$image_package" "$install_root" || return 1
	dpkg-deb -x "$1" "$install_root" || return 1
	image="$install_root/boot/vmlinuz-$release"
	modules="$install_root/lib/modules/$release"
	cp "$btf" "$install_root/boot/btf-$release" || return 1
	cp "$config" "$install_root/boot/config-$release" || return 1
	[ -s "$image" ] && [ -d "$modules" ] || {
		echo "kernel packages did not contain image and modules for $release" >&2
		return 1
	}
	validate_kernel_install "$install_root" || return 1
	stage_kernel_install
}

setup() {
	if [ "${VM:-1}" != 0 ]; then
		sudo rm -rf /opt/ghc /usr/local/lib/android /usr/share/dotnet
	fi

	if [ -z "${KERNEL_CI_ARTIFACT_DIR:-}" ]; then
		echo 'KERNEL_CI_ARTIFACT_DIR must name the downloaded artifact from github.com/shirudo-dev/kernel' >&2
		exit 1
	fi
	stage_kernel_ci_artifact "$KERNEL_CI_ARTIFACT_DIR" || exit 1

	# spatch opens libpython3.X.so by that name for the Python of its
	# rules, and only the -dev package installs it.
	set -- rpm coccinelle libpython3-dev
	if [ "${VM:-1}" != 0 ]; then
		set -- "$@" autoconf autoconf-archive automake cloud-image-utils \
			dracut-core file isc-dhcp-client libguestfs-tools libltdl-dev \
			libtool libzstd-dev qemu-system-x86 qemu-utils swtpm \
			swtpm-tools tpm2-tools libtss2-tcti-swtpm0t64
	fi
	mkdir -p build
	sudo BPF_VMLINUX_BTF="$PWD/$kernel/vmlinux.btf" \
		.github/scripts/vm-toolchain.sh "$@"

	# t0003 runs the kernel's checkpatch.pl, which check-style.sh fetches
	# into build/checkpatch/ on its first run; without it t0003 skips.
	sh .github/scripts/check-style.sh --types >/dev/null ||
		echo '::warning::no checkpatch.pl fetched; t0003 skips'

	if [ "${VM:-1}" != 0 ]; then
		# /dev/kvm belongs to root on the runner.
		echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
			sudo tee /etc/udev/rules.d/99-kvm.rules >/dev/null
		sudo udevadm control --reload-rules
		sudo udevadm trigger --name-match=kvm

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
	fi
}

case "${1:-}" in
setup|run) ;;
*)
	echo "usage: $0 setup|run [unit|functional|end2end]" >&2
	exit 2
	;;
esac

case "${2:-}" in
'') goals=tests ;;
unit) goals='-C testing unit ci-checks' ;;
functional|end2end) goals="-C testing $2" ;;
*)
	echo "usage: $0 setup|run [unit|functional|end2end]" >&2
	exit 2
	;;
esac

trap finish EXIT

restore_workspace_ownership

if [ "$1" = setup ]; then
	setup
	exit 0
fi

# shellcheck source=/dev/null
. build/vm-toolchain.env

export BPF_VMLINUX_BTF="$PWD/$kernel/vmlinux.btf"

# A guest that boots runs the suite in minutes; one that hangs, in
# emergency mode for instance, would otherwise hold the job for an hour.
export TEST_VM_TIMEOUT=900

sudo prlimit --pid "$$" --memlock=unlimited:unlimited

# sudo drops LD_LIBRARY_PATH even with -E and replaces PATH with its
# secure_path, and the OpenSSL 3.5 build needs both: for the openssl the
# config probes run and for every shirudo binary the tests run here.
# shellcheck disable=SC2086
sudo -E env PATH="$PATH" LD_LIBRARY_PATH="$LD_LIBRARY_PATH" make VM="${VM:-1}" $goals
