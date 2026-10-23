#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Prepare static target dependencies in the LVH guest, reusing the host cache.

set -eu

cache=/host/build/lvh-target-deps
openssl=/tmp/shirudo-openssl
curl_prefix=/tmp/shirudo-curl
tss=/tmp/shirudo-target-deps

install_distro_archives()
{
	install -m 0644 /usr/lib/x86_64-linux-gnu/libelf.a "$tss/lib/libelf.a"
	install -m 0644 /usr/lib/x86_64-linux-gnu/libz.a "$tss/lib/libz.a"
	install -m 0644 /usr/lib/x86_64-linux-gnu/libzstd.a "$tss/lib/libzstd.a"
	install -m 0644 /usr/lib/x86_64-linux-gnu/libluajit-5.1.a \
		"$tss/lib/libluajit-5.1.a"
}

if [ -s "$cache/openssl/lib/libcrypto.a" ] &&
	[ -s "$cache/curl/lib/libcurl.a" ] &&
	[ -s "$cache/lib/libtss2-esys.a" ] &&
	[ -s "$cache/lib/libelf.a" ]; then
	rm -rf "$openssl" "$curl_prefix" "$tss"
	cp -a "$cache/openssl" "$openssl"
	cp -a "$cache/curl" "$curl_prefix"
	mkdir -p "$tss"
	cp -a "$cache/lib" "$tss/"
	install_distro_archives
	exit 0
fi

rm -rf "$openssl" "$curl_prefix" "$tss" \
	/tmp/openssl-3.5.9 /tmp/curl-8.18.0
mkdir -p "$tss/lib"

curl -fsSL https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz \
	-o /tmp/openssl-3.5.9.tar.gz
tar -C /tmp -xf /tmp/openssl-3.5.9.tar.gz
cd /tmp/openssl-3.5.9
./Configure --prefix="$openssl" --openssldir=/etc/ssl \
	--libdir=lib no-shared no-module no-docs no-tests no-apps
make -j4
make install_sw

curl -fsSL https://curl.se/download/curl-8.18.0.tar.xz \
	-o /tmp/curl-8.18.0.tar.xz
tar -C /tmp -xf /tmp/curl-8.18.0.tar.xz
cd /tmp/curl-8.18.0
PKG_CONFIG_PATH="$openssl/lib/pkgconfig" \
CPPFLAGS="-I$openssl/include" \
LDFLAGS="-L$openssl/lib" \
./configure \
	--prefix="$curl_prefix" \
	--with-openssl="$openssl" \
	--with-ca-bundle=/etc/ssl/certs/ca-certificates.crt \
	--with-ca-path=/etc/ssl/certs \
	--enable-static \
	--disable-shared \
	--without-libpsl --without-brotli --without-zstd \
	--without-nghttp2 --without-nghttp3 --without-ngtcp2 \
	--without-libidn2 --without-librtmp --without-libssh2 \
	--without-libssh --without-libgsasl --without-winidn \
	--disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
	--disable-telnet --disable-tftp --disable-pop3 --disable-imap \
	--disable-smtp --disable-gopher --disable-mqtt --disable-smb \
	--disable-ftp --disable-file --disable-manual --disable-docs
make -j4
make install

git clone --depth 1 --branch 4.2.0 \
	https://github.com/tpm2-software/tpm2-tss.git \
	"$tss/tpm2-tss"
cd "$tss/tpm2-tss"
./bootstrap
PKG_CONFIG_PATH="$openssl/lib/pkgconfig" \
./configure \
	--prefix="$tss" \
	--libdir="$tss/lib" \
	--enable-static \
	--disable-shared \
	--enable-nodl \
	--disable-fapi \
	--disable-policy \
	--disable-tcti-cmd \
	--disable-tcti-i2c-ftdi \
	--disable-tcti-i2c-helper \
	--disable-tcti-libtpms \
	--disable-tcti-pcap \
	--disable-tcti-spi-ftdi \
	--disable-tcti-spi-helper \
	--disable-tcti-spi-ltt2go \
	--disable-tcti-spidev \
	--disable-tcti-mssim \
	--disable-tcti-swtpm
make -j4
make install

install -m 0644 "$openssl/lib/libcrypto.a" "$tss/lib/libcrypto.a"
install -m 0644 "$openssl/lib/libssl.a" "$tss/lib/libssl.a"
install_distro_archives

rm -rf "$cache"
mkdir -p "$cache"
cp -a "$openssl" "$cache/openssl"
cp -a "$curl_prefix" "$cache/curl"
cp -a "$tss/lib" "$cache/lib"
