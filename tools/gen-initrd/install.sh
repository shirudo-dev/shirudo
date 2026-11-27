#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# One-shot installer for a target: install the shirudo-target package,
# place the operator's certificate, put the kernel parameter the bpf
# keyring needs on the boot command line and rebuild the initrd with
# shirudo inside, so that the next reboot comes up in the production
# configuration (Documentation/internals/boot-flow.rst). Runtime and signed
# config images must be provisioned separately before the authenticated UKI
# is rebuilt.
#
#   curl -fsSL https://raw.githubusercontent.com/shirudo-dev/shirudo/main/tools/gen-initrd/install.sh |
#       bash -s -- --cert https://example.com/shirudo/cert.der --cert-sha256 <sha256>

set -euo pipefail

usage()
{
	cat <<'EOF'
usage: install.sh [options]

  --cert <file|url>      the operator's certificate (cert.der); also SHIRUDO_CERT
  --cert-sha256 <hex>    the SHA-256 of that file, which a URL requires;
                         also SHIRUDO_CERT_SHA256
  --version <tag>        release to install (default: latest); also SHIRUDO_VERSION
  --package <file>       install this package instead of downloading one;
                         also SHIRUDO_PACKAGE
  --no-cmdline           leave the boot command line alone
  --no-initrd            do not rebuild the initrd
  --switch-to-dracut     on a system using initramfs-tools, install dracut
                         in its place (it removes initramfs-tools)
  --dry-run              print what would be done
  -h, --help             this text
EOF
}

REPO=${SHIRUDO_REPO:-shirudo-dev/shirudo}
CMDLINE_PARAM="bpf.keyring_unsealed=1 dm_verity.keyring_unsealed=1"
CERT_DST=/var/lib/shirudo/keys/cert.der

cert=${SHIRUDO_CERT:-}
cert_sha256=${SHIRUDO_CERT_SHA256:-}
version=${SHIRUDO_VERSION:-}
package=${SHIRUDO_PACKAGE:-}
do_cmdline=1
do_initrd=1
switch_to_dracut=0
dry_run=0

while [ $# -gt 0 ]; do
	case "$1" in
	--cert) cert=${2:?}; shift 2 ;;
	--cert-sha256) cert_sha256=${2:?}; shift 2 ;;
	--version) version=${2:?}; shift 2 ;;
	--package) package=${2:?}; shift 2 ;;
	--no-cmdline) do_cmdline=0; shift ;;
	--no-initrd) do_initrd=0; shift ;;
	--switch-to-dracut) switch_to_dracut=1; shift ;;
	--dry-run) dry_run=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; printf 'install.sh: unknown option: %s\n' "$1" >&2; exit 2 ;;
	esac
done

say()
{
	printf 'shirudo install: %s\n' "$*"
}

die()
{
	printf 'shirudo install: %s\n' "$*" >&2
	exit 1
}

# Every state change goes through here, so --dry-run shows the plan.
run()
{
	if [ "$dry_run" = 1 ]; then
		printf '  + %s\n' "$*"
		return 0
	fi
	"$@"
}

# A certificate from a URL is whatever the server sent; only a digest the
# operator got another way makes it theirs.
check_cert_options()
{
	case "$cert_sha256" in
	'') ;;
	*[!0-9a-fA-F]*) die "--cert-sha256 takes 64 hex digits" ;;
	*) [ "${#cert_sha256}" = 64 ] || die "--cert-sha256 takes 64 hex digits" ;;
	esac
	cert_sha256=$(printf '%s' "$cert_sha256" | tr 'A-F' 'a-f')
	case "$cert" in
	http://*|https://*)
		[ -n "$cert_sha256" ] ||
			die "a certificate from a URL needs --cert-sha256 (sha256sum cert.der on the operator host)"
		;;
	'')
		[ -z "$cert_sha256" ] || die "--cert-sha256 needs --cert"
		;;
	esac
}

check_cert_options
[ "$dry_run" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (or --dry-run)"
command -v curl >/dev/null 2>&1 || [ -n "$package" ] || die "curl not found"

# ---- the package ---------------------------------------------------------

arch=$(uname -m)
case "$arch" in
x86_64) deb_arch=amd64 ;;
aarch64) deb_arch=arm64 ;;
riscv64) deb_arch=riscv64 ;;
*) die "unsupported architecture $arch" ;;
esac

if command -v dpkg >/dev/null 2>&1; then
	format=deb
elif command -v rpm >/dev/null 2>&1; then
	format=rpm
else
	format=tar
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The release's asset list, through the GitHub API; the package name
# carries the version, so it is matched by shape rather than spelled.
release_assets()
{
	local url

	if [ -n "$version" ]; then
		url="https://api.github.com/repos/$REPO/releases/tags/$version"
	else
		url="https://api.github.com/repos/$REPO/releases/latest"
	fi
	curl -fsSL -H 'Accept: application/vnd.github+json' "$url" |
		grep -o '"browser_download_url": *"[^"]*"' |
		sed 's/.*"\(https[^"]*\)"/\1/'
}

pick_asset()
{
	local pattern=$1

	grep -E -- "$pattern" | head -1
}

fetch_package()
{
	local assets asset sums

	say "looking up the ${version:-latest} release of $REPO"
	assets=$(release_assets) || die "cannot list the release assets"
	case "$format" in
	deb) asset=$(pick_asset "/shirudo-target_[^/]*_${deb_arch}\\.deb\$" <<<"$assets") ;;
	rpm) asset=$(pick_asset "/shirudo-target-[^/]*\\.${arch}\\.rpm\$" <<<"$assets") ;;
	tar) asset=$(pick_asset "/shirudo\\.tar\\.gz\$" <<<"$assets") ;;
	esac
	[ -n "$asset" ] || die "the release has no $format package for $arch"
	package=$tmp/${asset##*/}
	say "downloading ${asset##*/}"
	run curl -fsSL -o "$package" "$asset"
	sums=$(pick_asset '/SHA256SUMS$' <<<"$assets")
	if [ -n "$sums" ]; then
		run curl -fsSL -o "$tmp/SHA256SUMS" "$sums"
		if [ "$dry_run" = 0 ]; then
			(cd "$tmp" && sha256sum -c --ignore-missing SHA256SUMS) ||
				die "checksum mismatch for ${asset##*/}"
		fi
	else
		say "the release publishes no SHA256SUMS; the download is trusted on TLS alone"
	fi
}

install_package()
{
	case "$package" in
	*.deb)
		say "installing $package"
		run dpkg -i "$package" || run apt-get install -y -f
		;;
	*.rpm)
		say "installing $package"
		if command -v dnf >/dev/null 2>&1; then
			run dnf install -y "$package"
		else
			run rpm -Uvh "$package"
		fi
		;;
	*.tar.gz)
		say "unpacking $package"
		run mkdir -p "$tmp/unpack"
		run tar -C "$tmp/unpack" -xzf "$package"
		run sh "$tmp/unpack/install.sh"
		run systemctl enable shirudo.service
		;;
	*)
		die "unknown package format: $package"
		;;
	esac
}

# Fetched and checked before the package goes in, so that a certificate
# that does not match leaves the host as it was.
fetch_cert()
{
	case "$cert" in
	http://*|https://*)
		say "fetching the certificate from $cert"
		run curl -fsSL -o "$tmp/cert.der" "$cert"
		cert=$tmp/cert.der
		;;
	esac
	[ "$dry_run" = 1 ] || [ -s "$cert" ] || die "no certificate at $cert"
	[ -n "$cert_sha256" ] || return 0
	say "checking the certificate against its SHA-256"
	if [ "$dry_run" = 1 ] && [ ! -e "$cert" ]; then
		printf '  + check sha256 %s of %s\n' "$cert_sha256" "$cert"
	elif [ "$(sha256sum <"$cert" | cut -d' ' -f1)" != "$cert_sha256" ]; then
		die "the certificate at $cert does not have SHA-256 $cert_sha256"
	fi
}

[ -z "$cert" ] || fetch_cert
[ -n "$package" ] || fetch_package
[ "$dry_run" = 1 ] || [ -s "$package" ] || die "no package at $package"
install_package

# ---- the certificate -----------------------------------------------------

if [ -n "$cert" ]; then
	say "installing the certificate at $CERT_DST"
	run install -d -m 0700 "$(dirname "$CERT_DST")"
	run install -m 0644 "$cert" "$CERT_DST"
elif [ ! -s "$CERT_DST" ]; then
	say "no certificate given and none at $CERT_DST; the initrd cannot be built without one"
	do_initrd=0
	fi

# ---- the boot command line -----------------------------------------------

# Whichever tool owns the command line on this system gets the
# parameter; the result lands with the next boot.
set_cmdline()
{
	if grep -q -w -- "$CMDLINE_PARAM" /proc/cmdline 2>/dev/null; then
		say "the running kernel already carries $CMDLINE_PARAM"
	fi
	if command -v grubby >/dev/null 2>&1; then
		say "adding $CMDLINE_PARAM to every kernel through grubby"
		run grubby --update-kernel=ALL --args="$CMDLINE_PARAM"
		return
	fi
	if command -v update-grub >/dev/null 2>&1 && [ -d /etc/default/grub.d ]; then
		say "adding $CMDLINE_PARAM through /etc/default/grub.d/shirudo.cfg"
		if [ "$dry_run" = 1 ]; then
			printf '  + write /etc/default/grub.d/shirudo.cfg\n'
		else
			printf 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX %s"\n' \
				"$CMDLINE_PARAM" >/etc/default/grub.d/shirudo.cfg
		fi
		run update-grub
		return
	fi
	if [ -f /etc/kernel/cmdline ]; then
		say "adding $CMDLINE_PARAM to /etc/kernel/cmdline"
		if [ "$dry_run" = 1 ]; then
			printf '  + append to /etc/kernel/cmdline\n'
		elif ! grep -q -w -- "$CMDLINE_PARAM" /etc/kernel/cmdline; then
			sed -i "1s/\$/ $CMDLINE_PARAM/" /etc/kernel/cmdline
		fi
		if [ -d /boot/loader/entries ]; then
			local entry
			for entry in /boot/loader/entries/*.conf; do
				[ -f "$entry" ] || continue
				grep -q -w -- "$CMDLINE_PARAM" "$entry" && continue
				say "adding $CMDLINE_PARAM to $entry"
				run sed -i "/^options /s/\$/ $CMDLINE_PARAM/" "$entry"
			done
		fi
		say "a unified kernel image takes the parameter from its .cmdline section: rebuild it (kernel-install add) for it to apply"
		return
	fi
	say "no known boot loader configuration; add $CMDLINE_PARAM to the kernel command line yourself"
}

[ "$do_cmdline" = 0 ] || set_cmdline

# ---- the initrd ----------------------------------------------------------

build_initrd()
{
	local gen

	if ! command -v dracut >/dev/null 2>&1; then
		if command -v mkinitramfs >/dev/null 2>&1 && [ "$switch_to_dracut" = 1 ]; then
			say "replacing initramfs-tools with dracut"
			run apt-get update -q
			run apt-get install -y dracut
		elif command -v mkinitramfs >/dev/null 2>&1; then
			say "this system builds its initrd with initramfs-tools, which has no systemd and no PCR phase measurements; rerun with --switch-to-dracut to move to dracut, or build a dracut initrd yourself"
			return 1
		else
			say "dracut not found; install it and run shirudo-gen-initrd"
			return 1
		fi
	fi
	gen=$(command -v shirudo-gen-initrd || true)
	[ -n "$gen" ] || die "shirudo-gen-initrd not found; is the shirudo-target package installed?"
	say "rebuilding the initrd of $(uname -r) with shirudo inside"
	run "$gen" --kver "$(uname -r)"
}

initrd_ok=1
if [ "$do_initrd" = 1 ]; then
	build_initrd || initrd_ok=0
fi

# ---- summary -------------------------------------------------------------

if [ "$initrd_ok" = 1 ] && [ "$do_initrd" = 1 ] && [ "$do_cmdline" = 1 ]; then
	say "done; provision runtime and signed config images before rebuilding the UKI and rebooting"
else
	say "done; the production configuration needs the initrd rebuilt and $CMDLINE_PARAM on the command line"
fi
[ "$initrd_ok" = 1 ] || exit 2
