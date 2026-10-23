#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/target-tests.sh -- run the target suite in the test VM as
# make -C testing test-tgt does on a developer's host. setup makes the
# runner the VM host: KVM, the VM's packages, a compatible LVH kernel or
# the Shirudo test kernel cache, and the OpenSSL 3.5 toolchain from
# vm-toolchain.sh. staging builds the host bundle and runs the target suite
# from a dracut initrd.
#
#   .github/scripts/target-tests.sh setup|staging
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

# The LVH build and production run leave root's files behind.
finish() {
	status=$?
	restore_workspace_ownership || status=$?
	[ "$status" -eq 0 ] || diagnose
	exit "$status"
}

require_kernel_config() {
	config="$1"
	setting="$2"
	if ! grep -qx "$setting" "$config"; then
		printf 'LVH kernel config lacks %s\n' "$setting" >&2
		return 1
	fi
}

validate_lvh_kernel() {
	source_dir="$1"
	[ -d "$source_dir/boot" ] || {
		echo "LVH kernel artifacts are missing: $source_dir/boot" >&2
		return 1
	}

	set -- "$source_dir"/boot/vmlinuz-*
	[ "$#" -eq 1 ] && [ -s "$1" ] || {
		echo "expected one LVH vmlinuz in $source_dir/boot" >&2
		return 1
	}
	image="$1"
	release=${image##*/vmlinuz-}
	btf="$source_dir/boot/btf-$release"
	config="$source_dir/boot/config-$release"
	modules="$source_dir/lib/modules/$release"

	[ -s "$btf" ] || {
		echo "LVH kernel BTF is missing: $btf" >&2
		return 1
	}
	[ -s "$config" ] || {
		echo "LVH kernel config is missing: $config" >&2
		return 1
	}
	[ -d "$modules" ] || {
		echo "LVH kernel modules are missing: $modules" >&2
		return 1
	}
	grep -aq 'signature_size' "$btf" || {
		echo "LVH kernel BTF lacks bpf_attr.signature_size" >&2
		return 1
	}

	for setting in \
		CONFIG_BPF_EVENTS=y \
		CONFIG_BPF_LSM=y \
		CONFIG_BPF_SYSCALL=y \
		CONFIG_BPF_JIT=y \
		CONFIG_CGROUP_BPF=y \
		CONFIG_FUNCTION_TRACER=y \
		CONFIG_DYNAMIC_FTRACE=y \
		CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y \
		CONFIG_DEBUG_INFO_BTF=y \
		CONFIG_KEYS=y \
		CONFIG_ASYMMETRIC_KEY_TYPE=y \
		CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y \
		CONFIG_X509_CERTIFICATE_PARSER=y \
		CONFIG_PKCS7_MESSAGE_PARSER=y \
		CONFIG_TCG_TPM=y \
		CONFIG_TCG_TIS_CORE=y \
		CONFIG_TCG_TIS=y \
		CONFIG_TCG_CRB=y \
		CONFIG_SYSTEM_DATA_VERIFICATION=y \
		CONFIG_CRYPTO_MLDSA=y \
		CONFIG_CRYPTO_SHA512=y \
		CONFIG_CRYPTO_SHA256=y \
		CONFIG_MODULE_SIG=y \
		CONFIG_UPROBES=y \
		CONFIG_SECURITY=y \
		CONFIG_SECURITY_NETWORK=y \
		CONFIG_SECURITYFS=y \
		CONFIG_MODULES=y \
		CONFIG_PCI=y \
		CONFIG_PCI_MSI=y \
		CONFIG_PCIEPORTBUS=y \
		CONFIG_NETDEVICES=y \
		CONFIG_ETHERNET=y \
		CONFIG_IPV6=y \
		CONFIG_PACKET=y \
		CONFIG_ISO9660_FS=y \
		CONFIG_DEVTMPFS=y \
		CONFIG_DEVTMPFS_MOUNT=y \
		CONFIG_VIRTIO=y \
		CONFIG_VIRTIO_PCI=y \
		CONFIG_VIRTIO_BLK=y \
		CONFIG_VIRTIO_NET=y \
		CONFIG_NET_9P=y \
		CONFIG_NET_9P_VIRTIO=y \
		CONFIG_9P_FS=y \
		CONFIG_OVERLAY_FS=y \
		CONFIG_EXT4_FS=y \
		CONFIG_EXT4_FS_SECURITY=y \
		CONFIG_TMPFS=y \
		CONFIG_EFI_PARTITION=y \
		CONFIG_ACPI=y \
		CONFIG_PNP=y \
		CONFIG_PNPACPI=y \
		CONFIG_NETFILTER=y \
		CONFIG_NETFILTER_INGRESS=y \
		CONFIG_NET_NS=y \
		CONFIG_NF_CONNTRACK=y \
		CONFIG_NF_TABLES=m \
		CONFIG_VETH=m \
		CONFIG_BRIDGE=m \
		CONFIG_VLAN_8021Q=m \
		CONFIG_NF_FLOW_TABLE=m \
		CONFIG_NF_FLOW_TABLE_INET=m \
		CONFIG_NF_FLOW_TABLE_PROCFS=y \
		CONFIG_BLK_DEV_INITRD=y \
		CONFIG_RD_GZIP=y \
		CONFIG_RD_XZ=y \
		CONFIG_RD_ZSTD=y \
		CONFIG_BLK_DEV_LOOP=y \
		CONFIG_BLK_DEV_NVME=y \
		CONFIG_EFI=y \
		CONFIG_EFI_STUB=y \
		CONFIG_SERIAL_8250=y \
		CONFIG_SERIAL_8250_CONSOLE=y \
		CONFIG_PROC_FS=y
	do
		require_kernel_config "$config" "$setting" || return 1
	done
	return 0
}

stage_lvh_kernel() {
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

build_test_kernel() {
	# A restored kernel is older than the checkout of the script that
	# built it.
	if [ -s "$kernel/bzImage.sha256sum" ]; then
		touch "$kernel/bzImage.sha256sum"
	fi
	make -C testing kernel
}

setup() {
	sudo rm -rf /opt/ghc /usr/local/lib/android /usr/share/dotnet

	# /dev/kvm belongs to root on the runner.
	echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' |
		sudo tee /etc/udev/rules.d/99-kvm.rules >/dev/null
	sudo udevadm control --reload-rules
	sudo udevadm trigger --name-match=kvm

	if [ -n "${LVH_KERNEL_ARTIFACT_DIR:-}" ] &&
		validate_lvh_kernel "$LVH_KERNEL_ARTIFACT_DIR"; then
		stage_lvh_kernel || exit 1
	else
		if [ -n "${LVH_KERNEL_ARTIFACT_DIR:-}" ]; then
			printf '%s\n' \
				'::warning::LVH kernel is incompatible; using the target kernel cache or building it on a cache miss.'
		fi
		build_test_kernel
	fi

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
setup|staging) ;;
*)
	echo "usage: $0 setup|staging" >&2
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

# A guest that boots runs the suite in minutes; one that hangs, in
# emergency mode for instance, would otherwise hold the job for an hour.
export TEST_VM_TIMEOUT=900

sudo prlimit --pid "$$" --memlock=unlimited:unlimited

make -C testing test-vm-bundle
sudo -E env PATH="$PATH" make -C testing test-tgt TEST_VM_INITRD=1
