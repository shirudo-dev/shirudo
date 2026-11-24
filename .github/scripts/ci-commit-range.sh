#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/ci-commit-range.sh -- run a checker over the commits a
# GitHub event covers: every commit a pull request or merge group adds, or
# a push brings to the branch. A push whose previous tip is unknown, after
# a force push, is checked at the pushed tip alone.
#
#   .github/scripts/ci-commit-range.sh <command> [<argument>...]
#
# The command runs with the rev-list arguments for the range appended,
# the form check-dco.sh and check-style.sh take. The event comes from the
# environment the workflow sets: EVENT_NAME, and BASE_SHA and HEAD_SHA for
# a pull request or merge group, BEFORE_SHA and SHA for a push.

set -eu

[ $# -gt 0 ] || {
	printf 'usage: %s <command> [<argument>...]\n' "$0" >&2
	exit 2
}

if [ "${EVENT_NAME:-}" = pull_request ] ||
	[ "${EVENT_NAME:-}" = merge_group ]; then
	set -- "$@" "${BASE_SHA:?}..${HEAD_SHA:?}"
elif git cat-file -e "${BEFORE_SHA:-}^{commit}" 2>/dev/null; then
	set -- "$@" "$BEFORE_SHA..${SHA:?}"
else
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::notice::previous tip %s is unknown; checking the pushed tip alone\n' \
			"${BEFORE_SHA:-}"
	fi
	set -- "$@" -1 "${SHA:?}"
fi

exec "$@"
