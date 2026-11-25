#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-runtime-image.sh -- build a runtime image of the
# default size around a target binary, with throwaway keys, and report the
# space left. It fails once the binary has outgrown the default of
# shirudo-gen-runtime, which then needs raising.
#
#   .github/scripts/check-runtime-image.sh <target-binary>
#
# SHIRUDO names the operator binary that makes the keys, SHIRUDO_BUILD the
# signing helper and SHIRUDO_GEN_RUNTIME the generator. Each defaults to
# the one in the checkout.

set -eu

if [ "$#" -ne 2 ]; then
	printf 'usage: %s <runtime-binary> <bootstrap-binary>\n' "$0" >&2
	exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
shirudo=${SHIRUDO:-$root/shirudo}
builder=${SHIRUDO_BUILD:-$root/tools/shirudo-build/shirudo-build}
generator=${SHIRUDO_GEN_RUNTIME:-$root/tools/gen-image/shirudo-gen-runtime}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

if ! "$shirudo" genkey --keys-dir "$work/keys" >/dev/null 2>"$work/err"; then
	cat "$work/err" >&2
	exit 1
fi
printf '%s\n' \
	'config.verification_key = /run/shirudo/runtime/etc/shirudo/config-cert.der' \
	'config.pcr = 14' \
	'config.image = /var/lib/shirudo/images/config' >"$work/runtime.conf"

if ! "$generator" --binary "$1" --bootstrap-binary "$2" \
	--bootstrap-conf "$work/runtime.conf" \
	--cert "$work/keys/cert.der" --config-cert "$work/keys/cert.der" \
	--output "$work/runtime" --keys-dir "$work/keys" \
	--builder "$builder" >/dev/null 2>"$work/err"; then
	cat "$work/err" >&2
	if grep -q 'do not fit' "$work/err"; then
		printf 'shirudo: the default runtime image no longer holds %s; raise size= in tools/gen-image/shirudo-gen-runtime\n' "$1" >&2
	fi
	exit 1
fi

size=$(stat -c %s "$work/runtime.img")
free=$(debugfs -R stats "$work/runtime.img" 2>/dev/null |
	awk '/^Free blocks:/ { print $3 * 4 }')
printf 'shirudo: the default runtime image of %d MiB holds %s with %s KiB free\n' \
	"$((size / 1048576))" "$1" "$free"
