#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the host-side payload imported by testing/vm/run.sh. The bundle is
# shared by all VMs, while TPM state and the test workspace remain per-VM.
# The host prepares the VM images; build-bundle-payload.sh builds and signs
# the rest, in the build container unless BUILD_CONTAINER=0.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=testing/vm/arch.sh
. "${REPO_ROOT}/testing/vm/arch.sh"
BUNDLE_DIR="${TEST_VM_HOST_BUNDLE:-${REPO_ROOT}/build/test-vm/host-bundle}"
WORK_DIR="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
HOST_PRIVATE_DIR="${TEST_VM_HOST_PRIVATE_DIR:-/tmp/shirudo-test-vm-private-$(id -u)}"
RUNTIME_CACHE_DIR="${TEST_VM_RUNTIME_CACHE_DIR:-${WORK_DIR}/cache/runtime}"
LIBGUESTFS_KERNEL_CACHE="${WORK_DIR}/cache/libguestfs/ubuntu"
UBUNTU_CODENAME="${TEST_VM_UBUNTU_CODENAME:-resolute}"
PACKAGE_FILE="$REPO_ROOT/testing/vm/runtime-packages"
DEFAULT_ROOTFS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/ubuntu-26.04-server-cloudimg-${TEST_VM_ARCH_DEB}.img"
ROOTFS_URL="${TEST_VM_ROOTFS_URL:-$DEFAULT_ROOTFS_URL}"
ROOTFS_SHA256="${TEST_VM_ROOTFS_SHA256:-}"
ROOTFS_NAME="ubuntu-26.04-server-cloudimg-${TEST_VM_ARCH_DEB}.img"
ROOTFS_CACHE="${WORK_DIR}/cache/rootfs/${ROOTFS_NAME}"
LOCK_FILE="${BUNDLE_DIR}.lock"
STAMP_FILE="${TEST_VM_BUNDLE_STAMP:-${BUNDLE_DIR}/.stamp}"
STAMP_INPUTS="${TEST_VM_BUNDLE_INPUTS:-}"
PACKAGE_CERT="${TEST_VM_PACKAGE_CERT:-}"
OPERATOR_KEYS_DIR="${HOST_PRIVATE_DIR}/operator-keys"
RUNTIME_PREP_VERSION=4
TEST_VM_MODE=${TEST_VM_MODE:-verity}
RUNTIME_DISK_SIZE="${TEST_VM_RUNTIME_DISK_SIZE:-8G}"
BUILD_CONTAINER="${BUILD_CONTAINER:-1}"

log()
{
	printf '[test-vm-bundle] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

validate_host_private_dir()
{
	local repo_root host_private_dir

	repo_root="$(realpath -m "$REPO_ROOT")"
	host_private_dir="$(realpath -m "$HOST_PRIVATE_DIR")"
	[[ "$host_private_dir" != "$repo_root" &&
	   "$host_private_dir" != "$repo_root"/* ]] ||
		die "TEST_VM_HOST_PRIVATE_DIR must be outside the repository"
	install -d -m 0700 "$HOST_PRIVATE_DIR"
	chmod 0700 "$HOST_PRIVATE_DIR"
}

validate_package_cert()
{
	[[ -z "$PACKAGE_CERT" ]] && return 0
	[[ -f "$PACKAGE_CERT" && -r "$PACKAGE_CERT" && -s "$PACKAGE_CERT" ]] ||
		die "TEST_VM_PACKAGE_CERT is not a readable, non-empty regular file: $PACKAGE_CERT"
}

# require_command COMMAND DEB-PACKAGE [RPM-PACKAGE]
require_command()
{
	local command_name="$1" deb_package="$2" rpm_package="${3:-$2}"
	command -v "$command_name" >/dev/null 2>&1 ||
		die "missing host command: $command_name (install with: $(test_vm_install_cmd "$(test_vm_pkg "$deb_package" "$rpm_package")"))"
}

check_libguestfs_host()
{
	local kernel="" candidate
	if [[ -n "${SUPERMIN_KERNEL:-}" ]]; then
		[[ -r "$SUPERMIN_KERNEL" ]] ||
			die "SUPERMIN_KERNEL is not readable: $SUPERMIN_KERNEL"
	else
		for candidate in /boot/vmlinuz* /lib/modules/*/vmlinuz; do
			if [[ -r "$candidate" ]]; then
				kernel="$candidate"
				break
			fi
		done
		if [[ -z "$kernel" ]]; then
			prepare_ubuntu_libguestfs_kernel
			log "libguestfs host check: using cached Ubuntu $UBUNTU_CODENAME kernel"
		fi
	fi
	if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
		log "libguestfs host check: /dev/kvm unavailable; appliance will use slower TCG"
	else
		log "libguestfs host check: KVM available"
	fi
}

prepare_ubuntu_libguestfs_kernel()
{
	local cache_dir index metadata package version kernel_version filename deb tmp
	local module_package module_filename kernel_info module_info module_root

	require_command dpkg-deb dpkg
	cache_dir="$LIBGUESTFS_KERNEL_CACHE/$UBUNTU_CODENAME"
	index="$cache_dir/Packages.gz"
	metadata="$cache_dir/kernel.info"
	mkdir -p "$cache_dir"
	if [[ ! -s "$metadata" || "$(awk -F '\t' '{print NF; exit}' "$metadata")" != 5 ]]; then
		curl -fsSL --retry 3 \
			--output "${index}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/dists/${UBUNTU_CODENAME}-updates/main/binary-${TEST_VM_ARCH_DEB}/Packages.gz" \
			|| die "could not download Ubuntu $UBUNTU_CODENAME kernel package index"
		mv -- "${index}.tmp" "$index"
		kernel_info="$(awk -v want_arch="$TEST_VM_ARCH_DEB" -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package ~ /^linux-image-[0-9].*-generic$/ &&
				    arch == want_arch && version != "" && filename != "")
					print version "\t" package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$kernel_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no $TEST_VM_ARCH_DEB generic kernel package"
		IFS=$'\t' read -r version package filename <<<"$kernel_info"
		kernel_version="${package#linux-image-}"
		module_info="$(awk -v want="linux-modules-$kernel_version" \
			-v want_arch="$TEST_VM_ARCH_DEB" -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package == want && arch == want_arch && version != "" && filename != "")
					print package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$module_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no matching $kernel_version modules package"
		IFS=$'\t' read -r module_package module_filename <<<"$module_info"
		printf '%s\t%s\t%s\t%s\t%s\n' "$version" "$package" "$filename" \
			"$module_package" "$module_filename" >"${metadata}.tmp"
		mv -- "${metadata}.tmp" "$metadata"
	fi
	IFS=$'\t' read -r version package filename module_package module_filename <"$metadata"
	[[ -n "$version" && -n "$package" && -n "$filename" &&
	   -n "$module_package" && -n "$module_filename" ]] ||
		die "invalid cached Ubuntu kernel metadata: $metadata"
	kernel_version="${package#linux-image-}"
	deb="$cache_dir/$package.deb"
	if [[ ! -s "$deb" ]]; then
		curl -fsSL --retry 3 --output "${deb}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/$filename" ||
			die "could not download Ubuntu kernel package $package"
		mv -- "${deb}.tmp" "$deb"
	fi
	local module_deb="$cache_dir/$module_package.deb"
	if [[ ! -s "$module_deb" ]]; then
		curl -fsSL --retry 3 --output "${module_deb}.tmp" \
			"${TEST_VM_ARCH_MIRROR}/$module_filename" ||
			die "could not download Ubuntu kernel modules package $module_package"
		mv -- "${module_deb}.tmp" "$module_deb"
	fi
	version="${version%% *}"
	tmp="$cache_dir/.root.tmp.$$"
	rm -rf -- "$tmp"
	mkdir -p "$tmp"
	dpkg-deb -x "$deb" "$tmp"
	dpkg-deb -x "$module_deb" "$tmp"
	module_root="$tmp/lib/modules"
	[[ -d "$module_root/$kernel_version" ]] || module_root="$tmp/usr/lib/modules"
	if [[ ! -r "$module_root/$kernel_version/modules.dep" ]]; then
		if [[ "$module_root" == "$tmp/usr/lib/modules" ]]; then
			mkdir -p "$tmp/lib"
			ln -s ../usr/lib/modules "$tmp/lib/modules"
			module_root="$tmp/lib/modules"
		fi
		depmod -b "$tmp" "$kernel_version"
	fi
	[[ -r "$tmp/boot/vmlinuz-$kernel_version" &&
	   -r "$module_root/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package $package lacks a usable kernel/module tree"
	if [[ ! -r "$cache_dir/boot/vmlinuz-$kernel_version" ||
	      ! -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]]; then
		mkdir -p "$cache_dir/boot" "$cache_dir/lib"
		[[ -L "$cache_dir/lib/modules" ]] && rm -f -- "$cache_dir/lib/modules"
		mkdir -p "$cache_dir/lib/modules"
		cp -a "$tmp/boot/." "$cache_dir/boot/"
		cp -a "$module_root/." "$cache_dir/lib/modules/"
	fi
	[[ -r "$cache_dir/boot/vmlinuz-$kernel_version" &&
	   -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package lacks a usable kernel/module tree"
	rm -rf -- "$tmp"
	export SUPERMIN_KERNEL="$cache_dir/boot/vmlinuz-$kernel_version"
	export SUPERMIN_MODULES="$cache_dir/lib/modules/$kernel_version"
	export SUPERMIN_KERNEL_VERSION="$kernel_version"
	return 0
}

# Each entry is command:Debian package:RPM package.
for dependency in \
	"flock:util-linux:util-linux" "curl:curl:curl" \
	"sha256sum:coreutils:coreutils" "awk:gawk:gawk" \
	"qemu-img:qemu-utils:qemu-img" \
	"virt-customize:libguestfs-tools:guestfs-tools" \
	"gzip:gzip:gzip" "depmod:kmod:kmod"; do
	IFS=: read -r command_name deb_package rpm_package <<<"$dependency"
	require_command "$command_name" "$deb_package" "$rpm_package"
done
# The Debian libguestfs appliance brings up its network with dhclient,
# which Ubuntu 24.04 no longer installs; without it apt in the appliance
# reaches nothing.
[[ "$TEST_VM_HOST_PKG" != apt ]] || require_command dhclient isc-dhcp-client
check_libguestfs_host

resolve_rootfs()
{
	local sums expected actual tmp
	mkdir -p "$(dirname "$ROOTFS_CACHE")"
	if [[ -n "$ROOTFS_SHA256" ]]; then
		expected="${ROOTFS_SHA256,,}"
	elif [[ "$ROOTFS_URL" != "$DEFAULT_ROOTFS_URL" ]]; then
		die "a custom TEST_VM_ROOTFS_URL requires TEST_VM_ROOTFS_SHA256"
	else
		sums="${ROOTFS_CACHE}.SHA256SUMS"
		curl -fsSL --retry 3 --output "$sums" \
			https://cloud-images.ubuntu.com/releases/server/26.04/release/SHA256SUMS
		expected="$(awk -v name="*$ROOTFS_NAME" '$2 == name {print $1; exit}' "$sums")"
		rm -f -- "$sums"
	fi
	[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] ||
		die "could not determine a valid SHA-256 for $ROOTFS_NAME"
	if [[ -s "$ROOTFS_CACHE" ]]; then
		actual="$(sha256sum "$ROOTFS_CACHE" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || rm -f -- "$ROOTFS_CACHE"
	fi
	if [[ ! -s "$ROOTFS_CACHE" ]]; then
		tmp="${ROOTFS_CACHE}.tmp.$$"
		log "downloading Ubuntu runtime rootfs: $ROOTFS_URL"
		curl -fL --retry 3 --output "$tmp" "$ROOTFS_URL"
		actual="$(sha256sum "$tmp" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || {
			rm -f -- "$tmp"
			die "downloaded rootfs SHA-256 mismatch"
		}
		mv -- "$tmp" "$ROOTFS_CACHE"
	fi
	ROOTFS_DIGEST="$expected"
}

prepare_runtime_image()
{
	local package_digest disk_size_key
	package_digest="$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')"
	disk_size_key="${RUNTIME_DISK_SIZE//[^A-Za-z0-9]/_}"
	RUNTIME_KEY="rootfs-${ROOTFS_DIGEST}-packages-${package_digest}-disk-${disk_size_key}-v${RUNTIME_PREP_VERSION}"
	RUNTIME_IMAGE="$RUNTIME_CACHE_DIR/$RUNTIME_KEY.qcow2"
	if [[ ! -s "$RUNTIME_IMAGE" ]]; then
		"$REPO_ROOT/testing/vm/prepare-runtime.sh" \
			--rootfs "$ROOTFS_CACHE" \
			--cache-dir "$RUNTIME_CACHE_DIR" \
			--package-file "$PACKAGE_FILE" \
			--runtime-key "$RUNTIME_KEY" \
			--runtime-disk-size "$RUNTIME_DISK_SIZE" \
			--key-output "$RUNTIME_CACHE_DIR/.${RUNTIME_KEY}.key"
	fi
}

bundle_is_current()
{
	local input

	[[ -s "$BUNDLE_DIR/test-mode" &&
	   "$(cat "$BUNDLE_DIR/test-mode")" == "$TEST_VM_MODE" ]] || return 1

	[[ -f "$STAMP_FILE" && -n "$STAMP_INPUTS" ]] || return 1
	[[ -x "$BUNDLE_DIR/root/usr/local/bin/shirudo" ]] || return 1
	[[ -s "$BUNDLE_DIR/runtime-image-key" ]] || return 1
	[[ -s "$OPERATOR_KEYS_DIR/keys/signing_key.pem" ]] || return 1
	cmp -s "$OPERATOR_KEYS_DIR/keys/cert.der" \
		"$BUNDLE_DIR/fixtures/cert.der" || return 1
	[[ "$(<"$BUNDLE_DIR/runtime-image-key")" == "$RUNTIME_KEY" ]] || return 1
	[[ -s "$RUNTIME_IMAGE" ]] || return 1
	for input in $STAMP_INPUTS; do
		[[ -e "$input" ]] || return 1
		[[ "$input" -nt "$STAMP_FILE" ]] && return 1
	done
	return 0
}

# The container builds from a copy of the checkout, so that it shares no
# objects with the host's build, and keeps the static target dependencies it
# builds for its image and Makefile.target-deps. A file it reads from the
# host goes into the fixture work first, where the container sees it.
build_payload_in_container()
{
	local container="$REPO_ROOT/testing/container/run.sh" deps name
	local -a pass=(-e TARGET_DEPS_DIR -e TEST_VM_ARCH)

	deps="$WORK_DIR/cache/target-deps/$({
		"$container" --image
		cat "$REPO_ROOT/Makefile.target-deps"
	} | sha256sum | cut -c1-16)"
	mkdir -p "$deps"
	install -d -m 0700 "$FIXTURE_WORK/inputs"
	"$REPO_ROOT/testing/vm/list-source.sh" "$FIXTURE_WORK/inputs/source-files"
	for name in BPF_VMLINUX_BTF TEST_VM_PACKAGE_CERT \
		TEST_VM_BUILTIN_SIGNING_KEY TEST_VM_BUILTIN_SIGNING_CERT; do
		[[ -n "${!name:-}" ]] || continue
		install -m 0600 "${!name}" "$FIXTURE_WORK/inputs/$name"
		export "$name=$FIXTURE_WORK/inputs/$name"
		pass+=(-e "$name")
	done
	log "building the payload in $("$container" --image)"
	TARGET_DEPS_DIR="$deps" "$container" -v "$TMP_DIR" -v "$FIXTURE_WORK" \
		-v "$deps" "${pass[@]}" -- \
		"$REPO_ROOT/testing/vm/build-bundle-payload.sh" --from-copy \
		"$FIXTURE_WORK/inputs/source-files" "$TMP_DIR" "$FIXTURE_WORK"
}

command -v flock >/dev/null 2>&1 ||
	die "flock is required; install it with: $(test_vm_install_cmd util-linux)"

[[ "$TEST_VM_MODE" == verity ]] || die "TEST_VM_MODE must be verity"
validate_package_cert

mkdir -p "$(dirname "$BUNDLE_DIR")"
exec 9>"$LOCK_FILE"
flock 9
# The stamp takes the time before the build reads its inputs, so that one
# changed while it runs is newer and the next VM goal builds again.
STAMP_TIME="$(date +%s.%N)"
validate_host_private_dir

resolve_rootfs
prepare_runtime_image
# run.sh prepares the operator VM's image with prepare-runtime.sh as well,
# and needs the appliance kernel chosen above.
mkdir -p "$WORK_DIR/cache/libguestfs"
for name in SUPERMIN_KERNEL SUPERMIN_MODULES SUPERMIN_KERNEL_VERSION; do
	[[ -z "${!name:-}" ]] || printf 'export %s=%q\n' "$name" "${!name}"
done >"$WORK_DIR/cache/libguestfs/supermin.env"

if bundle_is_current; then
	log "reusing current host bundle: $BUNDLE_DIR"
	exit 0
fi

TMP_DIR="$(mktemp -d "${BUNDLE_DIR}.tmp.XXXXXX")"
FIXTURE_WORK="$(mktemp -d "${HOST_PRIVATE_DIR}/fixtures.XXXXXX")"
cleanup()
{
	rm -rf -- "$TMP_DIR" "$FIXTURE_WORK"
}
trap cleanup EXIT
if [[ "$BUILD_CONTAINER" == 0 ]]; then
	"$REPO_ROOT/testing/vm/build-bundle-payload.sh" "$TMP_DIR" "$FIXTURE_WORK"
else
	build_payload_in_container
fi
printf '%s\n' "$TEST_VM_MODE" >"$TMP_DIR/test-mode"

printf 'shirudo-test-vm-bundle-v1\n' >"$TMP_DIR/format"
printf 'vendored-tools\n' >"$TMP_DIR/dependency-mode"
printf 'shirudo-test-vm-bundle-stamp-v1\n' >"$TMP_DIR/.stamp"
printf '%s\n' "$RUNTIME_KEY" >"$TMP_DIR/runtime-image-key"

# The end-to-end test publishes a package the target trusts, with the key
# that signs the fixtures. Keep its private half outside the guest share.
rm -rf -- "$OPERATOR_KEYS_DIR"
install -d -m 0700 "$OPERATOR_KEYS_DIR"
cp -a "$FIXTURE_WORK/trusted" "$OPERATOR_KEYS_DIR/keys"
chmod 0600 "$OPERATOR_KEYS_DIR/keys/signing_key.pem"

rm -rf -- "$BUNDLE_DIR"
mv -- "$TMP_DIR" "$BUNDLE_DIR"
touch -d "@$STAMP_TIME" "$STAMP_FILE"
trap - EXIT
log "ready: $BUNDLE_DIR"
