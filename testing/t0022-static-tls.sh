#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

TARGET=../shirudo-target
OPERATOR=../shirudo

if ! command -v readelf >/dev/null 2>&1 || [ ! -x "$TARGET" ]; then
	test_skip_all 'target static profile has not been built'
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'target is static PIE without an interpreter or shared dependencies' '
	sh ../.github/scripts/check-static-target.sh "$TARGET" &&
	"$TARGET" version >"$WORK/version"
'

test_expect_success 'the static ELF checker rejects the dynamic operator' '
	! sh ../.github/scripts/check-static-target.sh "$OPERATOR"
'

test_expect_success 'the static ELF checker rejects non-PIE and search paths' '
	printf "int main(void) { return 0; }\n" |
		${CC:-cc} -x c - -static -o "$WORK/nonpie" &&
	! sh ../.github/scripts/check-static-target.sh "$WORK/nonpie" &&
	printf "int main(void) { return 0; }\n" |
		${CC:-cc} -x c - -static-pie -Wl,-rpath,/untrusted \
		-o "$WORK/rpath" &&
	! sh ../.github/scripts/check-static-target.sh "$WORK/rpath"
'

test_expect_success 'preload constructors run in the operator but not the target' '
	${CC:-cc} -shared -fPIC helper/test-preload.c -o "$WORK/preload.so" &&
	env LD_PRELOAD="$WORK/preload.so" SHIRUDO_PRELOAD_MARKER="$WORK/operator" \
		"$OPERATOR" version >"$WORK/operator-version" &&
	test -f "$WORK/operator" &&
	env LD_PRELOAD="$WORK/preload.so" SHIRUDO_PRELOAD_MARKER="$WORK/target" \
		"$TARGET" version >"$WORK/target-version" &&
	test ! -e "$WORK/target"
'

test_expect_success 'target binary has no shared TLS closure' '
	test -x "$TARGET" &&
	! readelf -d "$TARGET" | grep -Eq "lib(curl|ssl|crypto|mbedtls|mbedx509|mbedcrypto|gnutls)\\.so"
'

test_expect_success 'target binary embeds OpenSSL 3.5 or newer' '
	version=$(grep -a -o -m1 "OpenSSL 3\\.[0-9]*\\.[0-9]*" "$TARGET" | head -1) &&
	test -n "$version" &&
	minor=$(printf "%s" "$version" | cut -d. -f2) &&
	[ "$minor" -ge 5 ]
'

test_expect_success 'target has no libssh dependency' '
	! readelf -d "$TARGET" | grep -Eq "libssh\\.so"
'

test_expect_success 'target Shirudo runtime libraries are static' '
	! readelf -d "$TARGET" | grep -Eq "lib(z|tss2-esys|tss2-tctildr|elf|luajit-5\\.1)\\.so"
'

test_expect_success 'target binary has no OpenSSL or mbedTLS unresolved symbols' '
	! nm -u "$TARGET" | grep -Eq "(^| )(SSL|OPENSSL|EVP_|X509|CMS_|mbedtls_)"
'

test_expect_success 'operator binary retains dynamic TLS libraries' '
	test -x "$OPERATOR" &&
	readelf -d "$OPERATOR" | grep -q "libcurl.so" &&
	readelf -d "$OPERATOR" | grep -q "libssl.so" &&
	readelf -d "$OPERATOR" | grep -q "libcrypto.so"
'

test_done
