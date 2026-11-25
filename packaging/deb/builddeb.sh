#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Assemble one .deb from an already-staged install tree (built by
# `make install-target` / `install-operator` into a DESTDIR): write
# DEBIAN/control plus, for the target role, the systemd maintainer
# scripts, then invoke dpkg-deb. Driven by `make -C packaging bindeb-pkg`.
#
# usage: builddeb.sh <target|operator> <stagedir> <version> <arch> \
#                    <maintainer> <output.deb>

set -eu

if [ "$#" -ne 6 ]; then
	printf 'usage: %s <target|operator> <stagedir> <version> <arch> <maintainer> <out.deb>\n' \
	       "$0" >&2
	exit 2
fi

role=$1
stage=$2
raw_version=$3
arch=$4
maint=$5
out=$6
here=$(CDPATH= cd "$(dirname "$0")" && pwd)

sanitize_deb_version()
{
	v=$(printf '%s' "$1" | sed 's/^v//; s/[^A-Za-z0-9.+:~-]/./g')
	case "$v" in
	[0-9]*) ;;
	*) v="0~$v" ;;
	esac
	printf '%s\n' "$v"
}

version=$(sanitize_deb_version "$raw_version")

case "$role" in
target)
	pkg=shirudo-target
	other=shirudo-operator
	bins="$stage/usr/bin/shirudo $stage/usr/libexec/shirudo/shirudo-runtime"
	short="signed-BPF lockdown LSM platform (target node)"
	;;
operator)
	pkg=shirudo-operator
	other=shirudo-target
	bins="$stage/usr/bin/shirudo $stage/usr/libexec/shirudo/shirudo-build"
	short="signed-BPF lockdown LSM platform (operator tools)"
	;;
*)
	printf 'builddeb: unknown role "%s"\n' "$role" >&2
	exit 2
	;;
esac

depends=$("$here/depends.sh" $bins || true)
if [ "$role" = operator ]; then
	# Operator-only compilers and the standard image format/verify tool.
	depends="${depends:+$depends, }clang-23, llvm, cryptsetup-bin"
fi

# Installed-Size is in KiB, computed before DEBIAN/ exists.
size=$(du -s -k "$stage" 2>/dev/null | cut -f1)

mkdir -p "$stage/DEBIAN"

{
	printf 'Package: %s\n' "$pkg"
	printf 'Version: %s\n' "$version"
	printf 'Architecture: %s\n' "$arch"
	printf 'Section: admin\n'
	printf 'Priority: optional\n'
	printf 'Maintainer: %s\n' "$maint"
	[ -n "${size:-}" ] && printf 'Installed-Size: %s\n' "$size"
	[ -n "${depends:-}" ] && printf 'Depends: %s\n' "$depends"
	printf 'Conflicts: %s\n' "$other"
	printf 'Replaces: %s\n' "$other"
	printf 'Description: %s\n' "$short"
	if [ "$role" = target ]; then
		printf '%s\n' \
" shirudo locks down the bpf() syscall via a BPF LSM so that only signed," \
" in-kernel BPF loader programs can install BPF code, create maps or attach" \
" links -- even for CAP_SYS_ADMIN callers. This package installs the" \
" agentless target-node components: the shirudo binary and systemd units" \
" that re-mount the private bpffs, re-attach the LSM and re-apply the" \
" signed upatch set early on every boot, then periodically export upatch" \
" maps and status keepalives. It carries no private signing key."
	else
		printf '%s\n' \
" shirudo locks down the bpf() syscall via a BPF LSM so that only signed," \
" in-kernel BPF loader programs can install BPF code. This package installs" \
" the operator-side tooling: the shirudo binary plus shirudo-build, which" \
" compiles and CMS-signs .upatch artifacts. It is for the machine that holds" \
" the private signing key and produces artifacts for direct target loading;" \
" it does not install the" \
" target systemd units. It also installs shirudo-quote-check, which checks" \
" keepalive quotes for a telemetry backend."
	fi
} > "$stage/DEBIAN/control"

# Target-only: enable the reboot-persistence service and target timers on
# install, then disable them on removal. They activate on the next boot but
# are never auto-started by dpkg, since attaching the LSM is an operator
# decision rather than an installation side effect.
if [ "$role" = target ]; then
	cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = configure ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
	systemctl enable shirudo.service >/dev/null 2>&1 || true
	systemctl enable shirudo-map-export.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-keepalive.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-xdp-reconcile.timer >/dev/null 2>&1 || true
	udevadm control --reload >/dev/null 2>&1 || true
	systemctl enable shirudo-bpm-repo-update.timer >/dev/null 2>&1 || true
	systemctl enable shirudo-bpm-tree-sync.timer >/dev/null 2>&1 || true
	echo "shirudo: shirudo.service enabled; it runs 'shirudo init' early on the"
	echo "shirudo: next boot. To enforce now: systemctl start shirudo.service"
	echo "shirudo: shirudo-map-export.timer enabled for the next boot"
	echo "shirudo: shirudo-keepalive.timer enabled for the next boot"
	echo "shirudo: shirudo-xdp-reconcile.timer enabled for the next boot"
	echo "shirudo: shirudo-bpm-repo-update.timer enabled for the next boot"
	echo "shirudo: shirudo-bpm-tree-sync.timer enabled for the next boot"
fi
exit 0
EOF
	cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then
	systemctl --no-reload disable --now shirudo-map-export.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-keepalive.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-xdp-reconcile.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-bpm-repo-update.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable --now shirudo-bpm-tree-sync.timer \
		>/dev/null 2>&1 || true
	systemctl --no-reload disable shirudo.service >/dev/null 2>&1 || true
fi
exit 0
EOF
	cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if { [ "$1" = remove ] || [ "$1" = purge ]; } && \
   command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
EOF
	chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" \
	           "$stage/DEBIAN/postrm"
fi

dpkg-deb --root-owner-group --build "$stage" "$out" >/dev/null
printf 'shirudo: built %s (%s %s %s)\n' "$out" "$pkg" "$version" "$arch"
