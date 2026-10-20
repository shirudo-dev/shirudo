#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/gen-sbom.sh -- write an SPDX 2.3 software bill of
# materials next to each package, listing what it carries that a package
# manager cannot see: the target binary links OpenSSL, libcurl, TPM2-TSS
# and the distribution's libelf, zlib, zstd and LuaJIT archives
# statically, including the C and compiler runtimes, and both roles link
# the vendored libbpf.
#
#   .github/scripts/gen-sbom.sh <package>...
#
# Each <package> gets <package>.spdx.json beside it. A target package
# needs the SHIRUDO_TARGET_PKG_CONFIG_PATH and SHIRUDO_TARGET_STATIC_LIBDIR
# it was built with and a Debian-family build host: every archive in the
# static libdir has to be one of the source-built dependencies or belong
# to a distribution package, or the script fails rather than leave it
# out. The shirudo version is SHIRUDO_CI_VERSION, else git describe.
# CC must match the compiler used to link the target runtime.

set -eu

HOMEPAGE=https://github.com/shirudo-dev/shirudo

root=$(cd "$(dirname "$0")/../.." && pwd)

die() {
	printf 'gen-sbom: %s\n' "$*" >&2
	exit 1
}

if [ $# -eq 0 ]; then
	printf 'usage: %s <package>...\n' "$0" >&2
	exit 2
fi

command -v jq >/dev/null 2>&1 || die 'jq not found'

version=${SHIRUDO_CI_VERSION:-$(git -C "$root" describe --tags --always --dirty)}
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	created=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
	created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cpe() {
	printf 'cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*' "$1" "$2" "$3"
}

# component <name> <version> <license> <download> <purl> <source info> [<cpe>...]
component() {
	id=SPDXRef-Package-$(printf '%s' "$1" | tr -c 'A-Za-z0-9.-' '-')
	name=$1 ver=$2 lic=$3 dl=$4 purl=$5 src=$6
	shift 6
	jq -cn --arg id "$id" --arg name "$name" --arg ver "$ver" \
		--arg lic "$lic" --arg dl "$dl" --arg purl "$purl" --arg src "$src" '
		{
			SPDXID: $id,
			name: $name,
			versionInfo: $ver,
			downloadLocation: $dl,
			filesAnalyzed: false,
			licenseConcluded: "NOASSERTION",
			licenseDeclared: $lic,
			copyrightText: "NOASSERTION",
			primaryPackagePurpose: "LIBRARY",
			externalRefs: ([{
				referenceCategory: "PACKAGE-MANAGER",
				referenceType: "purl",
				referenceLocator: $purl
			}] + [$ARGS.positional[] | {
				referenceCategory: "SECURITY",
				referenceType: "cpe23Type",
				referenceLocator: .
			}])
		} + if $src == "" then {} else {sourceInfo: $src} end' --args "$@"
}

libbpf_component() {
	h=$root/vendor/libbpf/bpf/libbpf_version.h
	major=$(sed -n 's/^#define LIBBPF_MAJOR_VERSION \([0-9]*\)$/\1/p' "$h")
	minor=$(sed -n 's/^#define LIBBPF_MINOR_VERSION \([0-9]*\)$/\1/p' "$h")
	commit=$(sed -n 's/^commit=//p' "$root/vendor/libbpf/COMMIT")
	if [ -z "$major" ] || [ -z "$minor" ] || [ -z "$commit" ]; then
		die 'cannot read the libbpf version from vendor/libbpf'
	fi
	component libbpf "$major.$minor" 'LGPL-2.1-only OR BSD-2-Clause' \
		NOASSERTION "pkg:generic/libbpf@$major.$minor" \
		"vendored from tools/lib/bpf of the Linux tree at $commit" \
		"$(cpe libbpf_project libbpf "$major.$minor")"
}

deb_license() {
	case $1 in
	elfutils)	echo 'GPL-2.0-or-later OR LGPL-3.0-or-later' ;;
	zlib)		echo Zlib ;;
	libzstd)	echo 'BSD-3-Clause OR GPL-2.0-only' ;;
	luajit*)	echo MIT ;;
	glibc)		echo LGPL-2.1-or-later ;;
	gcc-*)		echo 'GPL-3.0-or-later WITH GCC-exception-3.1' ;;
	*)		echo NOASSERTION ;;
	esac
}

# The distribution package that installed <file> as <path>, or as the
# same path without /usr before the merge.
deb_component() {
	for p in "$2" "${2#/usr}"; do
		cmp -s "$1" "$p" 2>/dev/null || continue
		owner=$(dpkg -S "$p" 2>/dev/null | sed -n '/^diversion /!{s/: .*//;s/,.*//;p;q;}')
		[ -n "$owner" ] || continue
		read -r name ver arch srcpkg <<-EOF
		$(dpkg-query -W -f '${Package} ${Version} ${Architecture} ${source:Package}' "$owner")
		EOF
		[ -n "$srcpkg" ] || die "cannot query $owner"
		enc=$(printf '%s' "$ver" | sed 's/:/%3A/g; s/+/%2B/g')
		component "$name" "$ver" "$(deb_license "$srcpkg")" NOASSERTION \
			"pkg:deb/$os_id/$name@$enc?arch=$arch${distro:+&distro=$distro}&upstream=$srcpkg" \
			"built by $os_id from source package $srcpkg"
		return 0
	done
	die "cannot account for $1: no distribution package installed it as $2"
}

target_components() {
	if [ -z "${SHIRUDO_TARGET_PKG_CONFIG_PATH:-}" ] ||
	   [ -z "${SHIRUDO_TARGET_STATIC_LIBDIR:-}" ]; then
		die 'a target package needs SHIRUDO_TARGET_PKG_CONFIG_PATH and SHIRUDO_TARGET_STATIC_LIBDIR'
	fi
	command -v dpkg-query >/dev/null 2>&1 ||
		die 'a target package needs a Debian-family build host'
	libdir=$SHIRUDO_TARGET_STATIC_LIBDIR
	PKG_CONFIG_PATH=$SHIRUDO_TARGET_PKG_CONFIG_PATH:$libdir/pkgconfig
	export PKG_CONFIG_PATH

	v=$(pkg-config --modversion openssl) || die 'openssl.pc not found'
	ssldir=$(pkg-config --variable=libdir openssl)
	component openssl "$v" Apache-2.0 \
		"https://github.com/openssl/openssl/releases/download/openssl-$v/openssl-$v.tar.gz" \
		"pkg:generic/openssl@$v" '' "$(cpe openssl openssl "$v")"

	v=$(pkg-config --modversion libcurl) || die 'libcurl.pc not found'
	[ -f "$(pkg-config --variable=libdir libcurl)/libcurl.a" ] ||
		die 'libcurl.pc names no static libcurl.a'
	component curl "$v" curl "https://curl.se/download/curl-$v.tar.xz" \
		"pkg:generic/curl@$v" '' \
		"$(cpe haxx curl "$v")" "$(cpe haxx libcurl "$v")"

	v=$(pkg-config --modversion tss2-esys) || die 'tss2-esys.pc not found'
	cmp -s "$(pkg-config --variable=libdir tss2-esys)/libtss2-esys.a" \
		"$libdir/libtss2-esys.a" ||
		die "$libdir/libtss2-esys.a is not the one tss2-esys.pc describes"
	component tpm2-tss "$v" BSD-2-Clause \
		"git+https://github.com/tpm2-software/tpm2-tss.git@$v" \
		"pkg:generic/tpm2-tss@$v" '' \
		"$(cpe tpm2_software_stack_project tpm2_software_stack "$v")"

	for a in "$libdir"/*.a; do
		[ -f "$a" ] || die "no static archives in $libdir"
		case ${a##*/} in
		libssl.a|libcrypto.a)
			cmp -s "$a" "$ssldir/${a##*/}" ||
				die "$a is not the one openssl.pc describes"
			;;
		libtss2-*.a)
			;;
		*)
			deb_component "$a" "$TARGET_SYSTEM_LIBDIR/${a##*/}"
			;;
		esac
	done
	for runtime_name in libc.a libm.a libgcc.a libgcc_eh.a rcrt1.o; do
		runtime_path=$(${CC:-cc} -print-file-name="$runtime_name") ||
			die "cannot locate $runtime_name with ${CC:-cc}"
		[ -f "$runtime_path" ] ||
			die "compiler runtime missing: $runtime_name"
		runtime_path=$(readlink -f "$runtime_path")
		deb_component "$runtime_path" "$runtime_path"
	done
}

libbpf_component >"$work/common"

for pkg; do
	[ -f "$pkg" ] || die "$pkg: no such file"
	case ${pkg##*/} in
	shirudo-target_*.deb|shirudo-target-*.rpm|shirudo.tar.gz|shirudo-static.tar.gz)
		role=target
		;;
	shirudo-operator_*.deb|shirudo-operator-*.rpm)
		role=operator
		;;
	*)
		die "$pkg: not a shirudo package"
		;;
	esac

	cp "$work/common" "$work/components"
	if [ $role = target ]; then
		if [ ! -f "$work/target" ]; then
			if [ -z "${TARGET_SYSTEM_LIBDIR:-}" ]; then
				ma=$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null ||
				     gcc -print-multiarch)
				TARGET_SYSTEM_LIBDIR=/usr/lib/$ma
			fi
			os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
			distro=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
			distro=${distro:+$os_id-$distro}
			target_components >"$work/target"
		fi
		cat "$work/target" >>"$work/components"
	fi

	base=${pkg##*/}
	sum=$(sha256sum "$pkg" | cut -d' ' -f1)
	jq -n --slurpfile comps "$work/components" --arg name "shirudo-$role" \
		--arg file "$base" --arg ver "$version" --arg sum "$sum" \
		--arg created "$created" --arg home "$HOMEPAGE" \
		--arg ns "$HOMEPAGE/spdx/$base-$sum" '
		($comps | unique_by(.SPDXID)) as $c |
		"SPDXRef-Package-\($name)" as $id |
		{
			spdxVersion: "SPDX-2.3",
			dataLicense: "CC0-1.0",
			SPDXID: "SPDXRef-DOCUMENT",
			name: $file,
			documentNamespace: $ns,
			creationInfo: {
				created: $created,
				creators: ["Tool: shirudo-gen-sbom"]
			},
			packages: ([{
				SPDXID: $id,
				name: $name,
				versionInfo: $ver,
				packageFileName: $file,
				downloadLocation: "NOASSERTION",
				homepage: $home,
				filesAnalyzed: false,
				checksums: [{algorithm: "SHA256", checksumValue: $sum}],
				licenseConcluded: "NOASSERTION",
				licenseDeclared: "BSD-2-Clause",
				copyrightText: "NOASSERTION",
				primaryPackagePurpose: "INSTALL"
			}] + $c),
			relationships: ([{
				spdxElementId: "SPDXRef-DOCUMENT",
				relationshipType: "DESCRIBES",
				relatedSpdxElement: $id
			}] + [$c[] | {
				spdxElementId: $id,
				relationshipType: "CONTAINS",
				relatedSpdxElement: .SPDXID
			}])
		}' >"$pkg.spdx.json"
	printf 'gen-sbom: wrote %s.spdx.json\n' "$pkg"
done
