#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/build-debian.sh -- build on a Debian testing container of
# any architecture, with the distribution's compiler and libraries, which
# are new enough to need no toolchain of their own, and clang 23 from
# unstable through install-clang.sh: the binary and the shirudo-build
# helper, then the unit tests, the decoder test and the linkage check.
# The BPF objects are bytecode whatever the host, so the BTF can come from
# a kernel of another architecture.
#
#   .github/scripts/build-debian.sh <vmlinux-btf>
#
# Run as root in the checkout root, inside a throwaway container: it
# installs packages and changes the git configuration.

set -eu

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <vmlinux-btf>\n' "$0" >&2
	exit 2
fi
btf=$1

grep -aq 'signature_size' "$btf" || {
	echo "$btf lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel" >&2
	exit 1
}

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	git \
	openssl \
	pkgconf \
	python3 \
	libcurl4-openssl-dev \
	libelf-dev \
	libluajit-5.1-dev \
	libssl-dev \
	libtss2-dev \
	zlib1g-dev
sh .github/scripts/install-clang.sh

git config --global --add safe.directory "$PWD"
uname -m
cc --version | head -n 1

export BPF_VMLINUX_BTF="$btf"
make -j"$(nproc)"
make shirudo-build
make -C testing unit
# LuaJIT needs its state below 2^47, which the heap meets on some
# architectures and not others, and no unit test runs a decoder.
make -C testing build-operator
sh testing/run-tests.sh -t t3002 functional/upatch
sh .github/scripts/check-operator-linkage.sh shirudo \
	tools/shirudo-build/shirudo-build
