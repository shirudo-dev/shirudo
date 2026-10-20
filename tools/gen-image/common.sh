# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# shellcheck shell=bash

die()
{
	printf '%s: %s\n' "${0##*/}" "$*" >&2
	exit 1
}

require_command()
{
	command -v "$1" >/dev/null || die "$2"
}

require_new_output()
{
	[ ! -e "$1" ] && [ ! -L "$1" ] ||
		die "${2:-output} already exists: $1"
}

check_image_options()
{
	local output=$1 keys_dir=$2 size=$3 suffix

	[ -n "$output" ] || die '--output is required'
	[ -n "$keys_dir" ] && [ -d "$keys_dir" ] ||
		die '--keys-dir needs a directory'
	case "$size" in ''|*[!0-9]*) die '--size must be an integer in MiB' ;; esac
	[ "${#size}" -le 7 ] && [ "$size" -ge 8 ] && [ "$size" -le 1048576 ] ||
		die '--size must be between 8 and 1048576 MiB'
	for suffix in .img .verity .roothash .p7s; do
		require_new_output "$output$suffix"
	done
}

escape_sed_replacement()
{
	printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}
