#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1011 -- the bash completion completes from what the binary lists.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

SHIRUDO=$(cd .. && pwd)/shirudo
COMPLETION=$(cd .. && pwd)/completion/shirudo.bash
W=$(mktemp -d) || exit 1
trap 'rm -rf "$W"' EXIT

# What the completion offers for the words given, the last the one being
# completed, one a line.
complete_words() {
	bash -c '
		. "$1"
		shift
		COMP_WORDS=("$@")
		COMP_CWORD=$(($# - 1))
		_shirudo
		printf "%s\n" "${COMPREPLY[@]}"
	' complete "$COMPLETION" "$SHIRUDO" "$@"
}

test_expect_success 'commands and subcommands come from --list-cmds' '
	complete_words up >"$W/out" &&
	grep -qx upatch "$W/out" &&
	complete_words upatch lo >"$W/out" &&
	grep -qx load "$W/out" &&
	complete_words bpm config register "" >"$W/out" &&
	grep -qx add "$W/out" && grep -qx list "$W/out" &&
	grep -qx remove "$W/out"
'

test_expect_success 'options come from the command'"'"'s --list-opts' '
	complete_words upatch load --exp >"$W/out" &&
	grep -qx -- --expect-chain "$W/out" &&
	grep -qx -- --expect-version-id "$W/out" &&
	complete_words attest verify --ce >"$W/out" &&
	grep -qx -- --cert "$W/out" &&
	complete_words status -- >"$W/out" &&
	"$SHIRUDO" status --list-opts | cut -f1 | sort >"$W/want" &&
	sort "$W/out" | cmp -s - "$W/want"
'

test_expect_success 'a value gets what its placeholder asks for' '
	complete_words upatch map --js >"$W/out" &&
	grep -qx -- --json= "$W/out" &&
	mkdir "$W/keys" &&
	(cd "$W" && complete_words genkey --keys-dir k) >"$W/out" &&
	grep -qx keys "$W/out"
'

test_expect_success 'a leaf command lists no subcommands and logs nothing' '
	"$SHIRUDO" upatch load --list-cmds >"$W/out" 2>"$W/err" &&
	test ! -s "$W/out" && test ! -s "$W/err"
'

test_expect_success 'a path with a space is one file candidate' '
	mkdir "$W/dir with space" &&
	touch "$W/dir with space/release candidate.upatch" \
		"$W/dir with space/plain.txt" &&
	(cd "$W" && complete_words upatch info "dir with space/rel") >"$W/out" &&
	[ "$(wc -l <"$W/out")" -eq 1 ] &&
	grep -qx "dir with space/release candidate.upatch" "$W/out"
'

test_expect_success 'a path with a space is one directory candidate' '
	(cd "$W" && complete_words genkey --keys-dir "dir with") >"$W/out" &&
	[ "$(wc -l <"$W/out")" -eq 1 ] &&
	grep -qx "dir with space" "$W/out"
'

test_done
