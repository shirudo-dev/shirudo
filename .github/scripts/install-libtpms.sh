#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/install-libtpms.sh -- build the libtpms the host-side TPM
# simulator (testing/helper/tpmsim-cmd, used only by the functional TPM
# tests) links, at a commit newer than any distribution package. Ubuntu
# noble's 0.9.3 null-derefs inside NvReadRamIndexAttributes() when an
# orderly NV index's RAM entry goes missing across a save/restore cycle,
# which this test's tpm_open()/tpm_close()-per-cycle usage can trigger
# under load; fixed upstream by
# a0f832aaa50d52bf9a4f3cfd30e76573c1561d5b ("tpm2: Check orderly RAM
# entries against NV indices on state load"), not yet in a tagged
# release. Bump LIBTPMS_COMMIT and LIBTPMS_SHA256 together once one
# exists.
#
#   .github/scripts/install-libtpms.sh <cache-dir> [<install-prefix>]
#
# <cache-dir> is where the build is kept for the caller's own cache
# action, restored and saved around this script so a pinned commit is
# built once and reused across runs; it is rebuilt only when missing or
# when LIBTPMS_COMMIT changes (the caller keys its cache on this script's
# hash). <install-prefix>, if different from <cache-dir>, is where the
# build is actually used from, for a caller running inside a VM whose
# host mount is slower than its own disk; it defaults to <cache-dir>.
# Runs as root in a runner or LVH guest that is discarded afterwards.

set -eu

LIBTPMS_COMMIT=165c303ccc4784fb3d8cadbb3d71205641ba380b
LIBTPMS_SHA256=b5b4917ab5f9360377a93f74b406fbc2e5ee0a1a0b6d18018762793d03f48741

cache=$1
prefix=${2:-$1}

if [ -s "$cache/lib/libtpms.so" ]; then
	if [ "$prefix" != "$cache" ]; then
		rm -rf "$prefix"
		cp -a "$cache" "$prefix"
	fi
	exit 0
fi

apt-get update
apt-get install -y --no-install-recommends \
	autoconf \
	autoconf-archive \
	automake \
	build-essential \
	ca-certificates \
	curl \
	libssl-dev \
	libtool \
	pkg-config

rm -rf "$prefix" "/tmp/libtpms-$LIBTPMS_COMMIT"
tarball="libtpms-$LIBTPMS_COMMIT.tar.gz"
curl -fsSL --retry 3 -o "/tmp/$tarball" \
	"https://github.com/stefanberger/libtpms/archive/$LIBTPMS_COMMIT.tar.gz"
printf '%s  /tmp/%s\n' "$LIBTPMS_SHA256" "$tarball" | sha256sum -c --quiet
tar -C /tmp -xf "/tmp/$tarball"
cd "/tmp/libtpms-$LIBTPMS_COMMIT"
./autogen.sh
./configure --prefix="$prefix" --with-tpm2 --with-openssl
make -j"$(nproc)"
make install

if [ "$prefix" != "$cache" ]; then
	rm -rf "$cache"
	mkdir -p "$(dirname "$cache")"
	cp -a "$prefix" "$cache"
fi
