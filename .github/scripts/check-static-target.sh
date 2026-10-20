#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause

set -eu

export LC_ALL=C
readelf=${READELF:-readelf}

if [ "$#" -ne 1 ]; then
	printf 'usage: %s <target-binary>\n' "$0" >&2
	exit 2
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$readelf" -hW "$1" >"$work/header"
"$readelf" -lW "$1" >"$work/programs"
"$readelf" -dW "$1" >"$work/dynamic"

if ! grep -Eq 'Type:.*DYN' "$work/header" ||
   ! grep -Eq '\(FLAGS_1\).*PIE' "$work/dynamic" ||
   grep -Eq '[[:space:]]INTERP[[:space:]]' "$work/programs" ||
   grep -Eq '\((NEEDED|RPATH|RUNPATH)\)' "$work/dynamic"; then
	printf 'shirudo: %s must be static PIE without an interpreter, shared dependencies or library search paths\n' "$1" >&2
	exit 1
fi
