#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0046 -- .github/scripts/gen-sbom.sh: the SPDX documents a target and an
# operator package get, against a staged dependency tree and stub dpkg
# tools, and the archives it refuses to leave out.

cd "$(dirname "$0")"
. ./test-lib.sh
for t in jq pkg-config sha256sum; do
	command -v $t >/dev/null 2>&1 || test_skip_all "$t not installed"
done
S=$(cd .. && pwd)/.github/scripts/gen-sbom.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# A pkg-config file in <dir>/pkgconfig describing <dir>.
pc() {
	mkdir -p "$1/pkgconfig"
	printf 'libdir=%s\nName: %s\nDescription: %s\nVersion: %s\n' \
		"$1" "$2" "$2" "$3" >"$1/pkgconfig/$2.pc"
}

mkdir -p "$W/bin" "$W/sys" "$W/deps/lib" "$W/out"
echo elf >"$W/sys/libelf.a"
echo zlib >"$W/sys/libz.a"
for archive in libc.a libm.a libgcc.a libgcc_eh.a rcrt1.o; do
	printf '%s\n' "$archive" >"$W/sys/$archive"
done
pc "$W/openssl/lib" openssl 3.5.9
echo ssl >"$W/openssl/lib/libssl.a"
echo crypto >"$W/openssl/lib/libcrypto.a"
pc "$W/curl/lib" libcurl 8.18.0
echo curl >"$W/curl/lib/libcurl.a"
pc "$W/deps/lib" tss2-esys 4.1.3
echo esys >"$W/deps/lib/libtss2-esys.a"
cp "$W/openssl/lib/libssl.a" "$W/openssl/lib/libcrypto.a" \
	"$W/sys/libelf.a" "$W/sys/libz.a" "$W/deps/lib/"

cat >"$W/bin/dpkg" <<'EOF'
#!/bin/sh
case $2 in
*/libelf.a) echo "libelf-dev:amd64: $2" ;;
*/libz.a) echo "zlib1g-dev:amd64: $2" ;;
*/libc.a|*/libm.a|*/rcrt1.o) echo "libc6-dev:amd64: $2" ;;
*/libgcc.a|*/libgcc_eh.a) echo "libgcc-14-dev:amd64: $2" ;;
*) echo "dpkg-query: no path found matching pattern $2" >&2; exit 1 ;;
esac
EOF
cat >"$W/bin/dpkg-query" <<'EOF'
#!/bin/sh
for p; do :; done
case $p in
libelf-dev:amd64) echo 'libelf-dev 0.192-4 amd64 elfutils' ;;
zlib1g-dev:amd64) echo 'zlib1g-dev 1:1.3.dfsg+really1.3.1-1 amd64 zlib' ;;
libc6-dev:amd64) echo 'libc6-dev 2.42-1 amd64 glibc' ;;
libgcc-14-dev:amd64) echo 'libgcc-14-dev 14.2.0-19 amd64 gcc-14' ;;
*) exit 1 ;;
esac
EOF
cat >"$W/bin/cc" <<'EOF'
#!/bin/sh
root=$(CDPATH= cd "$(dirname "$0")/../sys" && pwd)
if [ "${SHIRUDO_TEST_UNOWNED_RUNTIME:-0}" = 1 ] &&
   [ "$1" = -print-file-name=libgcc.a ]; then
	printf '%s/unowned.a\n' "$root"
	exit 0
fi
printf '%s/%s\n' "$root" "${1#-print-file-name=}"
EOF
chmod +x "$W/bin/dpkg" "$W/bin/dpkg-query" "$W/bin/cc"

echo deb >"$W/out/shirudo-target_1.0_amd64.deb"
echo deb >"$W/out/shirudo-operator_1.0_amd64.deb"
mkdir -p "$W/img/shirudo-static-image/root/usr/local/bin"
echo target >"$W/img/shirudo-static-image/root/usr/local/bin/shirudo"
tar -C "$W/img" -czf "$W/out/shirudo-static.tar.gz" shirudo-static-image

run() {
	env PATH="$W/bin:$PATH" SHIRUDO_CI_VERSION=v1.0 SOURCE_DATE_EPOCH=0 \
		CC="$W/bin/cc" \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$W/curl/lib/pkgconfig:$W/openssl/lib/pkgconfig" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$W/deps/lib" \
		TARGET_SYSTEM_LIBDIR="$W/sys" "$@" >/dev/null 2>"$W/err"
}

# jq -e <filter> over the document of <package>.
doc() {
	jq -e "$2" "$W/out/$1.spdx.json" >/dev/null
}

T=shirudo-target_1.0_amd64.deb

test_expect_success 'a target package lists its static closure and libbpf' '
	run sh "$S" "$W/out/$T" &&
	doc $T "[.packages[].name] | sort == [\"curl\", \"libbpf\", \"libc6-dev\", \"libelf-dev\", \"libgcc-14-dev\", \"openssl\", \"shirudo-target\", \"tpm2-tss\", \"zlib1g-dev\"]" &&
	doc $T ".packages[] | select(.name == \"openssl\") | .versionInfo == \"3.5.9\"" &&
	doc $T ".packages[] | select(.name == \"tpm2-tss\") | .versionInfo == \"4.1.3\"" &&
	doc $T "[.relationships[] | select(.relationshipType == \"CONTAINS\")] | length == 8"
'

test_expect_success 'the document describes the package by its checksum and version' '
	sum=$(sha256sum "$W/out/$T" | cut -d" " -f1) &&
	doc $T ".spdxVersion == \"SPDX-2.3\" and .creationInfo.created == \"1970-01-01T00:00:00Z\"" &&
	doc $T ".packages[0].checksums[0].checksumValue == \"$sum\" and .packages[0].versionInfo == \"v1.0\"" &&
	doc $T ".relationships[0] == {spdxElementId: \"SPDXRef-DOCUMENT\", relationshipType: \"DESCRIBES\", relatedSpdxElement: \"SPDXRef-Package-shirudo-target\"}"
'

test_expect_success 'a distribution archive carries its deb purl and licence' '
	doc $T ".packages[] | select(.name == \"zlib1g-dev\") | .externalRefs[0].referenceLocator | test(\"^pkg:deb/[^/]+/zlib1g-dev@1%3A1.3.dfsg%2Breally1.3.1-1[?]arch=amd64&.*upstream=zlib$\")" &&
	doc $T ".packages[] | select(.name == \"libelf-dev\") | .licenseDeclared == \"GPL-2.0-or-later OR LGPL-3.0-or-later\""
'

test_expect_success 'the static tarball records embedded C and compiler runtimes' '
	run sh "$S" "$W/out/shirudo-static.tar.gz" &&
	doc shirudo-static.tar.gz ".packages[] | select(.name == \"libgcc-14-dev\") | .versionInfo == \"14.2.0-19\" and .licenseDeclared == \"GPL-3.0-or-later WITH GCC-exception-3.1\"" &&
	doc shirudo-static.tar.gz ".packages[] | select(.name == \"libc6-dev\") | .versionInfo == \"2.42-1\" and .licenseDeclared == \"LGPL-2.1-or-later\""
'

test_expect_success 'a missing compiler runtime fails' '
	mv "$W/sys/libgcc.a" "$W/sys/unowned.a" &&
	! run sh "$S" "$W/out/$T" &&
	mv "$W/sys/unowned.a" "$W/sys/libgcc.a" &&
	grep -q "compiler runtime missing: libgcc.a" "$W/err"
'

test_expect_success 'a compiler runtime without distribution provenance fails' '
	cp "$W/sys/libgcc.a" "$W/sys/unowned.a" &&
	! run env SHIRUDO_TEST_UNOWNED_RUNTIME=1 sh "$S" "$W/out/$T" &&
	grep -q "cannot account for .*unowned.a" "$W/err"
'

test_expect_success 'an operator package lists libbpf alone and needs no target build' '
	run env -u SHIRUDO_TARGET_PKG_CONFIG_PATH -u SHIRUDO_TARGET_STATIC_LIBDIR \
		sh "$S" "$W/out/shirudo-operator_1.0_amd64.deb" &&
	doc shirudo-operator_1.0_amd64.deb "[.packages[].name] | sort == [\"libbpf\", \"shirudo-operator\"]"
'

test_expect_success 'a static archive no package installed fails' '
	echo jent >"$W/deps/lib/libjitterentropy.a" &&
	! run sh "$S" "$W/out/$T" &&
	rm "$W/deps/lib/libjitterentropy.a" &&
	grep -q "cannot account for .*libjitterentropy.a" "$W/err"
'

test_expect_success 'a staged libssl.a other than the one openssl.pc describes fails' '
	echo other >"$W/deps/lib/libssl.a" &&
	! run sh "$S" "$W/out/$T" &&
	cp "$W/openssl/lib/libssl.a" "$W/deps/lib/libssl.a" &&
	grep -q "not the one openssl.pc describes" "$W/err"
'

test_expect_success 'a target package without its build environment fails' '
	! run env -u SHIRUDO_TARGET_STATIC_LIBDIR sh "$S" "$W/out/$T" &&
	grep -q SHIRUDO_TARGET_STATIC_LIBDIR "$W/err"
'

test_expect_success 'a file that is no shirudo package is refused' '
	echo x >"$W/out/other.deb" &&
	! run sh "$S" "$W/out/other.deb" &&
	grep -q "not a shirudo package" "$W/err"
'

test_done
