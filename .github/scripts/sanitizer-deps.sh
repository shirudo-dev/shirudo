#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Install the ASan, UBSan and TSan jobs' dependencies in a disposable LVH
# guest. Keep sid at a known working snapshot: a partial OCaml transition
# can otherwise make coccinelle uninstallable before the build starts.

set -eu

export DEBIAN_FRONTEND=noninteractive

# Replace all image sources so later installs, including install-clang.sh,
# use the same package set. Only the snapshot's expiry check is disabled;
# apt still verifies its signatures and package hashes.
rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources
echo 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261119T120000Z/ sid main' \
	>/etc/apt/sources.list

apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	coccinelle \
	cryptsetup-bin \
	e2fsprogs \
	curl \
	git \
	pkg-config \
	python3 \
	libcurl4-openssl-dev \
	libelf-dev \
	libluajit-5.1-dev \
	libpython3-dev \
	libtpms-dev \
	libtss2-dev \
	zlib1g-dev
sh .github/scripts/install-clang.sh libclang-rt-23-dev
