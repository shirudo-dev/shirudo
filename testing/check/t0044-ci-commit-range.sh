#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0044 -- .github/scripts/ci-commit-range.sh: the rev-list arguments a
# pull request, a push and a force push hand to a checker, on a throwaway
# repository.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
S=$(cd .. && pwd)/.github/scripts/ci-commit-range.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/repo
export GIT_AUTHOR_NAME='Random J Developer' GIT_AUTHOR_EMAIL='random@developer.example.org'
export GIT_COMMITTER_NAME='Random J Developer' GIT_COMMITTER_EMAIL='random@developer.example.org'
git init -q "$R"
git -C "$R" config commit.gpgsign false
git -C "$R" commit -q --allow-empty -m first
first=$(git -C "$R" rev-parse HEAD)
git -C "$R" commit -q --allow-empty -m second
second=$(git -C "$R" rev-parse HEAD)

# The checker under the script is printf, so its arguments come back one
# per line, the checker's own first.
run() {
	(cd "$R" && env "$@" sh "$S" printf '%s\n' own) >"$W/out" 2>"$W/err"
}

test_expect_success 'a pull request covers base..head after the command arguments' '
	run EVENT_NAME=pull_request BASE_SHA=$first HEAD_SHA=$second &&
	[ "$(sed -n 1p "$W/out")" = own ] &&
	[ "$(sed -n 2p "$W/out")" = "$first..$second" ]
'

test_expect_success 'a push covers the previous tip to the new one' '
	run EVENT_NAME=push BEFORE_SHA=$first SHA=$second &&
	[ "$(sed -n 2p "$W/out")" = "$first..$second" ]
'

test_expect_success 'a push from an unknown tip covers the new tip alone' '
	run EVENT_NAME=push BEFORE_SHA=0000000000000000000000000000000000000000 SHA=$second &&
	[ "$(sed -n 2p "$W/out")" = -1 ] &&
	[ "$(sed -n 3p "$W/out")" = "$second" ]
'

test_expect_success 'a pull request without its shas fails' '
	! run EVENT_NAME=pull_request
'

test_expect_success 'no command is a usage error' '
	! (cd "$R" && EVENT_NAME=push SHA=$second sh "$S") 2>"$W/err" &&
	grep -q "^usage:" "$W/err"
'

test_done
