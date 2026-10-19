#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
printf 'show:\n\t@echo $(TARGET_SYSTEM_LIBDIR)\n' >"$WORK/show.mk"

libdir() {
	multiarch=$1 root=$2
	shift 2
	env -u TARGET_SYSTEM_LIBDIR make -s -f ../Makefile.target-deps \
		-f "$WORK/show.mk" show TARGET_MULTIARCH="$multiarch" \
		TARGET_SYSTEM_ROOT="$root" "$@" 2>/dev/null
}

test_expect_success 'the system archives are found in the Debian multiarch directory' '
	mkdir -p "$WORK/deb/lib/aarch64-linux-gnu" &&
	: >"$WORK/deb/lib/aarch64-linux-gnu/libelf.a" &&
	test "$(libdir aarch64-linux-gnu "$WORK/deb")" = \
		"$WORK/deb/lib/aarch64-linux-gnu"
'

test_expect_success 'the system archives are found in lib64 where gcc has no multiarch name' '
	mkdir -p "$WORK/rpm/lib64" &&
	: >"$WORK/rpm/lib64/libelf.a" &&
	test "$(libdir "" "$WORK/rpm")" = "$WORK/rpm/lib64"
'

test_expect_success 'the multiarch directory wins over lib64 and lib' '
	mkdir -p "$WORK/all/lib/x86_64-linux-gnu" "$WORK/all/lib64" &&
	: >"$WORK/all/lib/x86_64-linux-gnu/libelf.a" &&
	: >"$WORK/all/lib64/libelf.a" &&
	: >"$WORK/all/lib/libelf.a" &&
	test "$(libdir x86_64-linux-gnu "$WORK/all")" = \
		"$WORK/all/lib/x86_64-linux-gnu"
'

test_expect_success 'a plain lib directory is found' '
	mkdir -p "$WORK/plain/lib" &&
	: >"$WORK/plain/lib/libelf.a" &&
	test "$(libdir "" "$WORK/plain")" = "$WORK/plain/lib"
'

test_expect_success 'without any archive the Debian path is reported' '
	mkdir -p "$WORK/none" &&
	test "$(libdir x86_64-linux-gnu "$WORK/none")" = \
		"$WORK/none/lib/x86_64-linux-gnu"
'

test_expect_success 'an explicit TARGET_SYSTEM_LIBDIR is kept' '
	test "$(libdir x86_64-linux-gnu "$WORK/rpm" TARGET_SYSTEM_LIBDIR=/elsewhere)" \
		= /elsewhere
'

test_done
