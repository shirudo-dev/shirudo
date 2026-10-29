#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

grep -qw bpf /sys/kernel/security/lsm
grep -aq 'signature_size' /sys/kernel/btf/vmlinux || {
	echo 'kernel BTF lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel' >&2
	exit 1
}

cd /host
apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	clang \
	cryptsetup-bin \
	e2fsprogs \
	llvm \
	python3 \
	pkg-config \
	autoconf \
	autoconf-archive \
	automake \
	doxygen \
	libacl1-dev \
	libftdi1-dev \
	libini-config-dev \
	libssl-dev \
	libfido2-dev \
	libtss2-dev \
	libelf-dev \
	zlib1g-dev \
	libzstd-dev \
	libcurl4-openssl-dev \
	libjson-c-dev \
	libtool \
	libtool-bin \
	libltdl-dev \
	libusb-1.0-0-dev \
	libluajit-5.1-dev \
	uuid-dev \
	dpkg-dev \
	rpm \
	curl \
	binutils \
	file \
	jq \
	git

git config --global --add safe.directory /host
sh .github/scripts/lvh-target-deps.sh
