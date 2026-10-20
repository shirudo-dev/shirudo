#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Assemble one binary .rpm from an already-staged install tree (built by
# `make install-target` / `install-operator` into a DESTDIR): generate a
# spec whose %install copies the stage into the buildroot, list every
# staged file, add the systemd scriptlets for the target role, then run
# rpmbuild -bb. Library dependencies come from rpm's ELF dependency
# generator (sonames), so the package installs on any RPM distribution
# that ships the same libraries. Driven by `make -C packaging binrpm-pkg`.
#
# usage: buildrpm.sh <target|operator> <stagedir> <version> <release> \
#                    <arch> <maintainer> <output.rpm>
set -eu
if [ "$#" -ne 7 ]; then
	printf 'usage: %s <target|operator> <stagedir> <version> <release> <arch> <maintainer> <out.rpm>\n' \
	       "$0" >&2
	exit 2
fi
role=$1
stage=$2
version=$3
release=$4
arch=$5
maint=$6
out=$7

case "$version" in
*-*|'') printf 'buildrpm: invalid rpm version "%s"\n' "$version" >&2; exit 2 ;;
esac
case "$release" in
*-*|'') printf 'buildrpm: invalid rpm release "%s"\n' "$release" >&2; exit 2 ;;
esac

case "$role" in
target)
	pkg=shirudo-target
	other=shirudo-operator
	short="signed-BPF lockdown LSM platform (target node)"
	;;
operator)
	pkg=shirudo-operator
	other=shirudo-target
	short="signed-BPF lockdown LSM platform (operator tools)"
	;;
*)
	printf 'buildrpm: unknown role "%s"\n' "$role" >&2
	exit 2
	;;
esac

command -v rpmbuild >/dev/null 2>&1 || {
	printf 'buildrpm: rpmbuild not found; install rpm (Debian/Ubuntu) or rpm-build (Fedora)\n' >&2
	exit 1
}

stage=$(CDPATH= cd "$stage" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/shirudo-rpm.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
spec=$work/$pkg.spec
mkdir -p "$work/BUILD" "$work/RPMS" "$work/buildroot"

# Every staged file, plus the directories shirudo itself owns. The FHS
# directories (/usr/bin, the systemd unit dir, ...) belong to the base
# system's filesystem package and are not claimed.
files=$(cd "$stage" && find . -mindepth 1 \( -type f -o -type l \) | sed 's#^\.##' | sort)
dirs=$(cd "$stage" && find . -mindepth 1 -type d -path '*/shirudo*' | sed 's#^\.#%dir #' | sort)
[ -n "$files" ] || { printf 'buildrpm: nothing staged under %s\n' "$stage" >&2; exit 1; }

{
	# No -debuginfo subpackage and no /usr/lib/.build-id links: the two
	# RPMs are the whole output, like the two debs.
	printf '%%global debug_package %%{nil}\n'
	printf '%%global _build_id_links none\n'
	if [ "$role" = target ]; then
		printf '%s\n' '%global __requires_exclude ^rtld[(]GNU_HASH[)]$'
	fi
	printf 'Name: %s\n' "$pkg"
	printf 'Version: %s\n' "$version"
	printf 'Release: %s\n' "$release"
	printf 'Summary: %s\n' "$short"
	printf 'License: BSD-2-Clause\n'
	printf 'Group: System Environment/Base\n'
	printf 'Packager: %s\n' "$maint"
	printf 'Conflicts: %s\n' "$other"
	if [ "$role" = operator ]; then
		# shirudo-build execs clang to compile .bpf.c upatches.
		printf 'Requires: clang, llvm\n'
	fi
	printf '\n%%description\n'
	if [ "$role" = target ]; then
		printf '%s\n' \
"shirudo locks down the bpf() syscall via a BPF LSM so that only signed," \
"in-kernel BPF loader programs can install BPF code, create maps or attach" \
"links -- even for CAP_SYS_ADMIN callers. This package installs the" \
"agentless target-node components: the shirudo binary and systemd units" \
"that re-mount the private bpffs, re-attach the LSM and re-apply the" \
"signed upatch set early on every boot, then periodically export upatch" \
"maps and status keepalives. It carries no private signing key."
	else
		printf '%s\n' \
"shirudo locks down the bpf() syscall via a BPF LSM so that only signed," \
"in-kernel BPF loader programs can install BPF code. This package installs" \
"the operator-side tooling: the shirudo binary plus shirudo-build, which" \
"compiles and CMS-signs .upatch artifacts. It is for the machine that holds" \
"the private signing key and produces artifacts for direct target loading;" \
"it does not install the target systemd units."
	fi
	printf '\n%%install\n'
	printf 'cp -a %s/. %%{buildroot}/\n' "$stage"
	printf '\n%%files\n'
	printf '%%defattr(-,root,root,-)\n'
	[ -z "$dirs" ] || printf '%s\n' "$dirs"
	printf '%s\n' "$files"
	# Target-only: enable the reboot-persistence service and target timers
	# on first install, then disable them on the last removal. They
	# activate on the next boot but are never auto-started by rpm, since
	# attaching the LSM is an operator decision rather than an installation
	# side effect. Plain systemctl calls rather than the distribution's
	# systemd macros, so the spec builds on any rpmbuild.
	if [ "$role" = target ]; then
		cat <<'EOF'

%post
if [ "$1" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl enable shirudo.service >/dev/null 2>&1 || true
	systemctl enable shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-keepalive.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-bpm-repo-update.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-bpm-tree-sync.timer >/dev/null 2>&1 || true
	echo "shirudo: shirudo.service enabled; it runs 'shirudo init' early on the"
	echo "shirudo: next boot. To enforce now: systemctl start shirudo.service"
	echo "shirudo: shirudo-map-export.timer enabled for the next boot"
	echo "shirudo: shirudo-keepalive.timer enabled for the next boot"
	echo "shirudo: shirudo-bpm-repo-update.timer enabled for the next boot"
	echo "shirudo: shirudo-bpm-tree-sync.timer enabled for the next boot"
fi
exit 0

%preun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
	systemctl --no-reload disable --now shirudo-map-export.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-keepalive.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-bpm-repo-update.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-bpm-tree-sync.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable shirudo.service >/dev/null 2>&1 || true
fi
exit 0

%postun
if [ "$1" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
	fi
} > "$spec"

rpmbuild -bb "$spec" \
	--target "$arch" \
	--buildroot "$work/buildroot" \
	--define "_topdir $work" \
	--define "_builddir $work/BUILD" \
	--define "_rpmdir $work/RPMS" \
	--define "_rpmfilename out.rpm" \
	>"$work/rpmbuild.log" 2>&1 || {
	cat "$work/rpmbuild.log" >&2
	exit 1
}
mv "$work/RPMS/out.rpm" "$out"
printf 'shirudo: built %s (%s %s-%s %s)\n' "$out" "$pkg" "$version" "$release" "$arch"
