#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/vm/kernel-artifact.sh -- the test VM's kernel, which
# github.com/shirudo-dev/kernel builds and this checkout does not.
#
#   kernel-artifact.sh fetch         download the kernel-packages-x86-64-ci
#                                    artifact of the pinned run and stage it
#   kernel-artifact.sh stage <dir>   stage an artifact already downloaded
#   kernel-artifact.sh run-id        print the pinned run
#
# Staging extracts the image and headers packages, checks the BTF for the
# signed-loader ABI and every LSM hook a program of bpf/ attaches to, and
# puts image, BTF, configuration and modules under
# artifacts/bpf-next-kernel-debs/, where testing/Makefile looks for them.
# With VM=0 it stages the BTF alone, which a build needs.
#
#   KERNEL_RUN_ID   another run of the kernel project's package workflow
#                   than the pinned one.
#
# fetch needs gh, logged in with read access to the kernel repository.

set -eu

# The run every trigger of the CI suite tests on, so that a new build of
# the kernel does not change what a series is tested on.
PINNED_RUN_ID=44367017434
ARTIFACT=kernel-packages-x86-64-ci
REPOSITORY=shirudo-dev/kernel

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

fetch() {
	id=$(run_id) || return 1
	[ "$(uname -m)" = x86_64 ] || {
		echo "the kernel project publishes a CI kernel for x86-64 only" >&2
		return 1
	}
	command -v gh >/dev/null 2>&1 || {
		echo "gh is needed to download $ARTIFACT of $REPOSITORY run $id" >&2
		return 1
	}
	download=build/kernel-ci-artifact
	rm -rf "$download"
	mkdir -p "$download" || return 1
	echo "downloading $ARTIFACT of $REPOSITORY run $id" >&2
	gh run download "$id" --repo "$REPOSITORY" --name "$ARTIFACT" \
		--dir "$download" || {
		echo "cannot download $ARTIFACT of $REPOSITORY run $id" >&2
		return 1
	}
	stage_kernel_ci_artifact "$download" || return 1
	printf '%s\n' "$id" >"$kernel/kernel-run-id"
}

case "${1:-}" in
fetch)
	[ $# -eq 1 ] || { echo "usage: kernel-artifact.sh fetch" >&2; exit 2; }
	fetch
	;;
stage)
	[ $# -eq 2 ] || { echo "usage: kernel-artifact.sh stage <dir>" >&2; exit 2; }
	stage_kernel_ci_artifact "$staged_from"
	;;
run-id)
	run_id
	;;
*)
	echo "usage: kernel-artifact.sh fetch|stage <dir>|run-id" >&2
	exit 2
	;;
esac
