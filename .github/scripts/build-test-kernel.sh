#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

sudo rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc
sudo apt-get update
sudo apt-get install --no-install-recommends -y \
	bc bison build-essential clang-20 gnu-coreutils cpio debhelper dpkg-dev \
	fakeroot flex libelf-dev libncurses-dev libssl-dev lld-20 llvm-20-dev \
	lsb-release make pahole pkg-config python3 rsync xz-utils zstd

# Ubuntu 26.04's uutils install -D races under parallel dtbs_install.
mkdir -p "$RUNNER_TEMP/gnu-coreutils-bin"
ln -sf /usr/bin/gnuinstall "$RUNNER_TEMP/gnu-coreutils-bin/install"
PATH="$RUNNER_TEMP/gnu-coreutils-bin:$PATH" \
	testing/kernel/build-kernel.sh --llvm 20 --arch "$1"
