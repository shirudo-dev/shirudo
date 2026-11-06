#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/vm-toolchain.sh -- prepare the LVH guest a workflow builds
# in, or the runner itself: check that the kernel the BPF objects are
# built for takes signed BPF, install clang 23 with install-clang.sh and the
# build dependencies, and build or reuse an OpenSSL 3.5 toolchain, since the
# distribution's predates ML-DSA. The
# environment the build then needs is written to build/vm-toolchain.env
# for the caller to source.
#
#   .github/scripts/vm-toolchain.sh [<apt package>...]
#
# Packages beyond the build dependencies, a sanitizer runtime for
# instance, go on the command line. The kernel is the running one unless
# BPF_VMLINUX_BTF names the BTF of another, as on a runner that builds for
# the test VM. Runs as root, from any directory; git is not available
# until it has been installed, so the checkout is found from the script's
# own path.

set -eu

OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

root=$(cd "$(dirname "$0")/../.." && pwd)
OPENSSL_PREFIX=$root/build/host-openssl
OPENSSL_STAMP=$OPENSSL_PREFIX/.shirudo-openssl-built

openssl_ready() {
	[ -f "$OPENSSL_STAMP" ] &&
		[ -x "$OPENSSL_PREFIX/bin/openssl" ] &&
		[ -s "$OPENSSL_PREFIX/lib/libcrypto.so.3" ] &&
		[ -s "$OPENSSL_PREFIX/lib/libssl.so.3" ] || return 1

	version=$(LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib" \
		"$OPENSSL_PREFIX/bin/openssl" version -v 2>/dev/null) || return 1
	case "$version" in
	"OpenSSL $OPENSSL_VERSION"|"OpenSSL $OPENSSL_VERSION "*) return 0 ;;
	esac
	return 1
}

btf=${BPF_VMLINUX_BTF:-/sys/kernel/btf/vmlinux}
grep -aq 'signature_size' "$btf" || {
	echo "$btf lacks bpf_attr.signature_size; needs a signed-BPF capable bpf-next kernel" >&2
	exit 1
}

sh "$root/.github/scripts/install-clang.sh"
apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	cryptsetup-bin \
	e2fsprogs \
	curl \
	git \
	pkg-config \
	python3 \
	libcurl4-openssl-dev \
	libelf-dev \
	libluajit-5.1-dev \
	libtpms-dev \
	libtss2-dev \
	zlib1g-dev \
	"$@"

# The checkout is mounted from the host under another owner.
git config --global --add safe.directory "$root"

if ! openssl_ready; then
	rm -rf "$OPENSSL_PREFIX"
	tarball=openssl-$OPENSSL_VERSION.tar.gz
	curl -fsSL --retry 3 -o "/tmp/$tarball" \
		"https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$tarball"
	printf '%s  /tmp/%s\n' "$OPENSSL_SHA256" "$tarball" | sha256sum -c --quiet
	tar -C /tmp -xf "/tmp/$tarball"
	cd "/tmp/openssl-$OPENSSL_VERSION"
	./Configure --prefix="$OPENSSL_PREFIX" --openssldir=/etc/ssl --libdir=lib \
		no-docs no-tests
	make -j"$(nproc)"
	make install_sw
	cd "$root"
	LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib" \
		"$OPENSSL_PREFIX/bin/openssl" version -v | \
		grep -F "OpenSSL $OPENSSL_VERSION" >/dev/null
	touch "$OPENSSL_STAMP"
else
	echo "using cached OpenSSL $OPENSSL_VERSION from $OPENSSL_PREFIX"
fi

mkdir -p build
cat >build/vm-toolchain.env <<EOT
export PATH=$OPENSSL_PREFIX/bin:\$PATH
export PKG_CONFIG_PATH=$OPENSSL_PREFIX/lib/pkgconfig
export LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib
EOT
