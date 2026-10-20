#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0032 -- packaging/rpm/buildrpm.sh assembles the two binary RPMs from a
# staged install tree the way `make -C packaging binrpm-pkg` does, without rebuilding
# the tree: stage a stand-in binary and the real systemd units, build the
# target and operator packages, and check their metadata, file lists,
# automatic soname requires and systemd scriptlets with rpm itself.
# Needs rpmbuild (rpm on Debian/Ubuntu, rpm-build on Fedora).

cd "$(dirname "$0")"
. ./test-lib.sh

command -v rpmbuild >/dev/null 2>&1 || test_skip_all "no rpmbuild"
command -v rpm >/dev/null 2>&1 || test_skip_all "no rpm"
command -v cc >/dev/null 2>&1 || test_skip_all "no C compiler"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
REPO=$(cd .. && pwd)
ARCH=$(rpm --eval '%{_arch}')

# A real ELF binary so rpm's dependency generator has something to read.
printf 'int main(void) { return 0; }\n' >"$WORK/stub.c"
cc -o "$WORK/stub" "$WORK/stub.c" 2>/dev/null || test_skip_all "cannot build a stub binary"

stage_target() {
	s=$1
	mkdir -p "$s/usr/bin" "$s/usr/lib/systemd/system" \
		"$s/usr/share/bash-completion/completions"
	install -m 0755 "$WORK/stub" "$s/usr/bin/shirudo"
	for unit in shirudo.service shirudo-map-export.service \
		shirudo-map-export.timer shirudo-keepalive.service \
		shirudo-keepalive.timer shirudo-bpm-repo-update.service \
		shirudo-bpm-repo-update.timer shirudo-bpm-tree-sync.service \
		shirudo-bpm-tree-sync.timer; do
		src=$REPO/systemd/$unit
		[ -e "$src" ] || src=$REPO/systemd/$unit.in
		sed 's|@bindir@|/usr/bin|g' "$src" >"$s/usr/lib/systemd/system/$unit"
	done
	install -m 0644 "$REPO/completion/shirudo.bash" \
		"$s/usr/share/bash-completion/completions/shirudo"
}

stage_operator() {
	s=$1
	mkdir -p "$s/usr/bin" "$s/usr/libexec/shirudo" "$s/usr/share/shirudo/bpf/include/bpf" \
		"$s/usr/share/bash-completion/completions"
	install -m 0755 "$WORK/stub" "$s/usr/bin/shirudo"
	install -m 0755 "$WORK/stub" "$s/usr/libexec/shirudo/shirudo-build"
	printf '/* stub */\n' >"$s/usr/share/shirudo/vmlinux.h"
	printf '/* stub */\n' >"$s/usr/share/shirudo/bpf/include/bpf/bpf_helpers.h"
	install -m 0644 "$REPO/completion/shirudo.bash" \
		"$s/usr/share/bash-completion/completions/shirudo"
}

stage_target "$WORK/target"
stage_operator "$WORK/operator"

test_expect_success 'buildrpm.sh builds the target package' '
	../packaging/rpm/buildrpm.sh target "$WORK/target" 1.2.3 1.5.gabc123 "$ARCH" \
		"Test <test@example.invalid>" "$WORK/target.rpm" >"$WORK/target.out" 2>&1 &&
	test -s "$WORK/target.rpm" &&
	grep -q "built .*target.rpm (shirudo-target 1.2.3-1.5.gabc123 $ARCH)" "$WORK/target.out"
'

test_expect_success 'target package metadata names, conflicts and version' '
	rpm -qp --qf "%{NAME} %{VERSION} %{RELEASE} %{ARCH} %{LICENSE}\n" "$WORK/target.rpm" \
		>"$WORK/target.info" 2>/dev/null &&
	grep -qx "shirudo-target 1.2.3 1.5.gabc123 $ARCH BSD-2-Clause" "$WORK/target.info" &&
	rpm -qp --conflicts "$WORK/target.rpm" | grep -qx "shirudo-operator" &&
	rpm -qp --qf "%{PACKAGER}\n" "$WORK/target.rpm" | grep -q "test@example.invalid"
'

test_expect_success 'target package lists the binary, every unit and the completion' '
	rpm -qpl "$WORK/target.rpm" >"$WORK/target.files" 2>/dev/null &&
	grep -qx /usr/bin/shirudo "$WORK/target.files" &&
	grep -qx /usr/lib/systemd/system/shirudo.service "$WORK/target.files" &&
	grep -qx /usr/lib/systemd/system/shirudo-map-export.timer "$WORK/target.files" &&
	grep -qx /usr/lib/systemd/system/shirudo-bpm-tree-sync.timer "$WORK/target.files" &&
	grep -qx /usr/share/bash-completion/completions/shirudo "$WORK/target.files" &&
	! grep -qx /usr/bin "$WORK/target.files" &&
	! grep -q "libexec/shirudo" "$WORK/target.files" &&
	test "$(wc -l <"$WORK/target.files")" -eq 11
'

test_expect_success 'library requirements come from the ELF dependency generator' '
	rpm -qp --requires "$WORK/target.rpm" >"$WORK/target.requires" 2>/dev/null &&
	grep -q "^libc.so.6" "$WORK/target.requires" &&
	! grep -q "clang" "$WORK/target.requires"
'

test_expect_success 'target scriptlets enable units on install and remove them safely' '
	rpm -qp --scripts "$WORK/target.rpm" >"$WORK/target.scripts" 2>/dev/null &&
	grep -q "^postinstall scriptlet" "$WORK/target.scripts" &&
	grep -q "systemctl enable shirudo.service" "$WORK/target.scripts" &&
	grep -q "systemctl enable shirudo-map-export.timer" "$WORK/target.scripts" &&
	grep -q "systemctl enable shirudo-keepalive.timer" "$WORK/target.scripts" &&
	grep -q "systemctl enable shirudo-bpm-repo-update.timer" "$WORK/target.scripts" &&
	grep -q "systemctl enable shirudo-bpm-tree-sync.timer" "$WORK/target.scripts" &&
	grep -q "^preuninstall scriptlet" "$WORK/target.scripts" &&
	grep -q "systemctl --no-reload disable --now shirudo-map-export.timer" "$WORK/target.scripts" &&
	grep -q "systemctl --no-reload disable --now shirudo-bpm-tree-sync.timer" "$WORK/target.scripts" &&
	grep -q "systemctl --no-reload disable shirudo.service" "$WORK/target.scripts" &&
	grep -q "^postuninstall scriptlet" "$WORK/target.scripts" &&
	! grep -qE "^[[:space:]]*systemctl (start|restart)" "$WORK/target.scripts"
'

test_expect_success 'buildrpm.sh builds the operator package with the compiler requirement' '
	../packaging/rpm/buildrpm.sh operator "$WORK/operator" 1.2.3 1 "$ARCH" \
		"Test <test@example.invalid>" "$WORK/operator.rpm" >/dev/null 2>&1 &&
	rpm -qp --qf "%{NAME} %{VERSION} %{RELEASE}\n" "$WORK/operator.rpm" |
		grep -qx "shirudo-operator 1.2.3 1" &&
	rpm -qp --conflicts "$WORK/operator.rpm" | grep -qx "shirudo-target" &&
	rpm -qp --requires "$WORK/operator.rpm" | grep -qx clang &&
	rpm -qp --requires "$WORK/operator.rpm" | grep -qx llvm &&
	rpm -qpl "$WORK/operator.rpm" >"$WORK/operator.files" &&
	grep -qx /usr/libexec/shirudo "$WORK/operator.files" &&
	grep -qx /usr/libexec/shirudo/shirudo-build "$WORK/operator.files" &&
	grep -qx /usr/share/shirudo/vmlinux.h "$WORK/operator.files" &&
	grep -qx /usr/share/shirudo/bpf/include/bpf/bpf_helpers.h "$WORK/operator.files" &&
	! grep -q "systemd" "$WORK/operator.files" &&
	test -z "$(rpm -qp --scripts "$WORK/operator.rpm")"
'

test_expect_success 'buildrpm.sh rejects a dash in version or release and an unknown role' '
	! ../packaging/rpm/buildrpm.sh target "$WORK/target" 1.2-3 1 "$ARCH" m "$WORK/bad.rpm" >/dev/null 2>&1 &&
	! ../packaging/rpm/buildrpm.sh target "$WORK/target" 1.2.3 1-2 "$ARCH" m "$WORK/bad.rpm" >/dev/null 2>&1 &&
	! ../packaging/rpm/buildrpm.sh gateway "$WORK/target" 1.2.3 1 "$ARCH" m "$WORK/bad.rpm" >/dev/null 2>&1 &&
	! test -e "$WORK/bad.rpm"
'

test_expect_success 'make -C packaging binrpm-pkg stages both roles and runs buildrpm.sh for each' '
	(cd .. && make -n -C packaging binrpm-pkg TARGET_DEPS_PREBUILT=1 \
		RPM_RAW_VERSION=v1.2.3-5-gabc123 >"$WORK/plan" 2>&1) &&
	grep -q "install-target" "$WORK/plan" &&
	grep -q "install-operator" "$WORK/plan" &&
	grep -q "buildrpm.sh target " "$WORK/plan" &&
	grep -q "buildrpm.sh operator " "$WORK/plan" &&
	test "$(grep -c "'"'"'1.2.3'"'"' '"'"'1.5.gabc123'"'"' '"'"'$ARCH'"'"'" "$WORK/plan")" -eq 2 &&
	grep -q "shirudo-target-1.2.3-1.5.gabc123.$ARCH.rpm" "$WORK/plan" &&
	grep -q "shirudo-operator-1.2.3-1.5.gabc123.$ARCH.rpm" "$WORK/plan"
'

test_expect_success 'PKG_ROLES=operator leaves the target package and its static build out' '
	(cd .. && make -n -C packaging binrpm-pkg PKG_ROLES=operator RPM_RAW_VERSION=v1.0.0 >"$WORK/plan-op" 2>&1) &&
	! grep -q "install-target" "$WORK/plan-op" &&
	! grep -q "buildrpm.sh target" "$WORK/plan-op" &&
	grep -q "buildrpm.sh operator" "$WORK/plan-op" &&
	grep -q "shirudo-build" "$WORK/plan-op" &&
	(cd .. && make -n -C packaging bindeb-pkg PKG_ROLES=target TARGET_DEPS_PREBUILT=1 \
		>"$WORK/plan-deb" 2>&1) &&
	grep -q "install-target" "$WORK/plan-deb" &&
	! grep -q "install-operator" "$WORK/plan-deb" &&
	! grep -q "builddeb.sh operator" "$WORK/plan-deb"
'

test_expect_success 'static PIE target packages do not require a shared runtime or loader' '
	cc -static-pie -static-libgcc -o "$WORK/static-stub" "$WORK/stub.c" &&
	install -m 0755 "$WORK/static-stub" "$WORK/target/usr/bin/shirudo" &&
	../packaging/rpm/buildrpm.sh target "$WORK/target" 1.2.3 1 "$ARCH" \
		"Test <test@example.invalid>" "$WORK/static.rpm" \
		>"$WORK/static.out" 2>&1 &&
	rpm -qp --requires "$WORK/static.rpm" >"$WORK/static.requires" 2>/dev/null &&
	! grep -Eq "^lib.*\\.so|^rtld\\(" "$WORK/static.requires"
'

test_done
