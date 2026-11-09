#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/vm/list-source.sh <output> -- write the files git sees in the
# checkout, tracked and untracked but not ignored, NUL-separated, for the
# copies the build container and the operator VM make of it. Neither can ask
# git itself: the .git of a linked worktree names a directory outside the
# checkout, which they do not see.

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
[ $# -eq 1 ] || {
	printf 'usage: %s <output>\n' "$0" >&2
	exit 2
}
# Root without SUDO_UID, as under systemd-run, cannot prove the checkout
# its own to git.
git -c safe.directory='*' -C "$root" ls-files -z -co --exclude-standard \
	>"$1" || {
	printf '%s: cannot list the files of %s with git; the build container and the operator VM copy what git sees, and BUILD_CONTAINER=0 builds the bundle in place\n' \
		"$0" "$root" >&2
	exit 1
}
