#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/vm/kernel-artifact.sh -- download and stage the test VM kernel.
#
#   kernel-artifact.sh fetch         download and stage the CI artifact for
#                                    the test VM architecture
#   kernel-artifact.sh download      download and extract it into build/
#                                    kernel-ci-artifact without staging
#   kernel-artifact.sh stage <dir>   stage an artifact already downloaded
#   kernel-artifact.sh run-id        print the pinned run
#
# Staging extracts the image package and the matching headers package
# when present. It checks the BTF for the signed-loader ABI and every
# LSM hook a program in bpf/ attaches to. It puts the image, BTF,
# configuration and modules under artifacts/bpf-next-kernel-debs/,
# where testing/Makefile looks for them.
# With VM=0 it stages the BTF alone and invalidates the staged VM kernel
# if the BTF changes.
#
#   KERNEL_RUN_ID   another run of shirudo's Build kernel packages workflow.
#
# Fetch the pinned prerelease with curl and python3, or an explicit
# run override with gh and Actions read access to shirudo.

set -eu

# The run every trigger of the CI suite tests on, so that a new build of
# the kernel does not change what a series is tested on.
PINNED_RUN_ID=45212180772
PINNED_ARM64_SHA256=13967ee9310eca1d175e9d17ee2f06254de4a9e4ab90e8b9a2f992fcba4b599b
PINNED_AMD64_SHA256=f3e660ce7b1e0cea8d3d1c19d8f3a75097c8aa9cf1dbc10b7ad81abfa2134a9b
KERNEL_REPOSITORY=shirudo-dev/shirudo

# A directory named from where the caller stands.
[ "${1:-}" != stage ] || [ $# -ne 2 ] || staged_from=$(realpath -- "$2")
cd "$(dirname "$0")/../.."

kernel=artifacts/bpf-next-kernel-debs

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
	printf 'kernel BTF lacks the LSM hooks%s: use a build from testing/kernel\n' \
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

clear_kernel_stamps() {
	rm -f "$kernel/bzImage.sha256sum" "$kernel/Image.sha256sum" \
		"$kernel/vmlinux.btf.sha256sum" "$kernel/kernel-run-id"
}

stage_kernel_install() {
	clear_kernel_stamps || return 1
	rm -rf "$kernel/lib/modules" || return 1
	mkdir -p "$kernel/lib/modules" || return 1
	cp "$image" "$kernel/$kernel_image_name" || return 1
	cp "$btf" "$kernel/vmlinux.btf" || return 1
	cp "$config" "$kernel/kernel.config" || return 1
	cp -a "$modules" "$kernel/lib/modules/" || return 1
	(
		cd "$kernel" || exit 1
		sha256sum vmlinux.btf > vmlinux.btf.sha256sum || exit 1
		sha256sum "$kernel_image_name" > "$kernel_image_name.sha256sum"
	) || return 1
}

stage_kernel_ci_artifact() {
	artifact_dir="$1"
	expected_arch="${2:-}"
	set -- "$artifact_dir"/*/linux-image-*.deb
	[ -e "$1" ] || set -- "$artifact_dir"/linux-image-*.deb
	[ "$#" -eq 1 ] && [ -s "$1" ] || {
		echo "expected one kernel image package in $artifact_dir" >&2
		return 1
	}
	image_package="$1"
	package_arch=${image_package##*_}
	package_arch=${package_arch%.deb}
	if [ -n "$expected_arch" ] && [ "$package_arch" != "$expected_arch" ]; then
		echo "expected a $expected_arch kernel image package: $image_package" >&2
		return 1
	fi
	case "$package_arch" in
	amd64) kernel_image_name=bzImage ;;
	arm64) kernel_image_name=Image ;;
	*)
		echo "expected an x86-64 or arm64 kernel image package: $image_package" >&2
		return 1
		;;
	esac
	package_dir=${image_package%/*}
	release=${image_package##*/linux-image-}
	release=${release%%_*}
	btf="$package_dir/vmlinux-$release.btf"
	[ -s "$btf" ] || {
		echo "kernel CI artifact lacks BTF for $release" >&2
		return 1
	}
	if [ "${VM:-1}" = 0 ]; then
		cmp -s "$btf" "$kernel/vmlinux.btf" && return 0
		mkdir -p "$kernel" || return 1
		clear_kernel_stamps || return 1
		cp "$btf" "$kernel/vmlinux.btf" || return 1
		return 0
	fi

	set -- "$package_dir"/linux-headers-"$release"_*_"$package_arch".deb
	headers_package=
	if [ "$#" -eq 1 ] && [ -s "$1" ]; then
		headers_package="$1"
	elif [ "$#" -gt 1 ] || [ -e "$1" ]; then
		echo "expected headers package for kernel $release in $package_dir" >&2
		return 1
	fi
	config="$package_dir/config-$release"
	[ -s "$config" ] || {
		echo "kernel CI artifact lacks config for $release" >&2
		return 1
	}
	install_root="$PWD/build/kernel-ci-extract"
	rm -rf "$install_root" || return 1
	mkdir -p "$install_root" || return 1
	dpkg-deb -x "$image_package" "$install_root" || return 1
	if [ -n "$headers_package" ]; then
		dpkg-deb -x "$headers_package" "$install_root" || return 1
	fi
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

run_id() {
	id=${KERNEL_RUN_ID:-$PINNED_RUN_ID}
	case "$id" in
	'' | *[!0-9]*)
		echo "KERNEL_RUN_ID must be numeric: $id" >&2
		return 1
		;;
	esac
	printf '%s\n' "$id"
}

download_ci_artifact() {
	id=$(run_id) || return 1
	# shellcheck source=testing/vm/arch.sh
	. testing/vm/arch.sh
	[ "$TEST_VM_ARCH_SUPPORTED" = 1 ] || {
		echo "no CI kernel artifact for $TEST_VM_ARCH" >&2
		return 1
	}
	artifact=$TEST_VM_ARCH_CI_ARTIFACT
	download=build/kernel-ci-artifact
	rm -rf "$download" || return 1
	mkdir -p "$download" || return 1
	echo "downloading $artifact from kernel build run $id" >&2

	if [ "$id" != "$PINNED_RUN_ID" ]; then
		command -v gh >/dev/null 2>&1 || {
			echo "gh is needed to download $artifact of $KERNEL_REPOSITORY run $id" >&2
			return 1
		}
		gh run download "$id" --repo "$KERNEL_REPOSITORY" --name "$artifact" --dir "$download"
		return
	fi

	asset=$artifact.zip
	archive=$download/$asset
	url=https://github.com/$KERNEL_REPOSITORY/releases/download/test-kernel-$id/$asset
	curl --fail --silent --show-error --location --output "$archive" "$url" || return 1
	case "$TEST_VM_ARCH_DEB" in
	arm64) checksum=$PINNED_ARM64_SHA256 ;;
	amd64) checksum=$PINNED_AMD64_SHA256 ;;
	esac
	printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status || {
		echo "SHA-256 mismatch for $asset from run $id" >&2
		return 1
	}
	python3 -m zipfile -e "$archive" "$download" || return 1
	rm -f "$archive"
}

fetch() {
	download_ci_artifact || return 1
	stage_kernel_ci_artifact "$download" "$TEST_VM_ARCH_DEB" || return 1
	if [ "${VM:-1}" = 0 ] && [ -s "$kernel/$kernel_image_name.sha256sum" ]; then
		return 0
	fi
	printf '%s\n' "$id" >"$kernel/kernel-run-id"
}

usage() {
	echo "usage: kernel-artifact.sh fetch|download|stage <dir>|run-id" >&2
	exit 2
}

case "${1:-}" in
fetch)
	[ $# -eq 1 ] || usage
	fetch
	;;
download)
	[ $# -eq 1 ] || usage
	download_ci_artifact
	;;
stage)
	[ $# -eq 2 ] || usage
	stage_kernel_ci_artifact "$staged_from"
	;;
run-id)
	run_id
	;;
*)
	usage
	;;
esac
