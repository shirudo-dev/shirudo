#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the OpenSSL 3.5+ toolchain the sanitizer suite needs, reusing the
# host cache: the distribution's OpenSSL predates ML-DSA, and the suite
# generates its test keys with the openssl binary. The build does not
# depend on the compiler under test, so one cache entry serves every
# matrix leg.

set -eu

OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

cache=/host/build/sanitizer-openssl
openssl=/tmp/shirudo-openssl

if [ -s "$cache/lib/libcrypto.so" ]; then
	rm -rf "$openssl"
	cp -a "$cache" "$openssl"
	exit 0
fi

rm -rf "$openssl" "$cache" "/tmp/openssl-$OPENSSL_VERSION"
tarball="openssl-$OPENSSL_VERSION.tar.gz"
curl -fsSL --retry 3 -o "/tmp/$tarball" \
	"https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/$tarball"
printf '%s  /tmp/%s\n' "$OPENSSL_SHA256" "$tarball" | sha256sum -c --quiet
tar -C /tmp -xf "/tmp/$tarball"
cd "/tmp/openssl-$OPENSSL_VERSION"
./Configure --prefix="$openssl" --openssldir=/etc/ssl --libdir=lib \
	no-docs no-tests
make -j4
make install_sw

mkdir -p "$(dirname "$cache")"
cp -a "$openssl" "$cache"
