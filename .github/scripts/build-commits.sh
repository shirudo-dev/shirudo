#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/build-commits.sh -- build every commit in a range on its
# own, oldest first, so that the history bisects as
# Documentation/contribute/code/contributing.rst asks: the binary, the
# shirudo-build helper, the quote checker and the test helpers. The first
# commit that does not build is named and the ones after it are not tried.
#
#   .github/scripts/build-commits.sh [<rev-list arguments>]
#
# The arguments go to git rev-list: a range such as origin/main..HEAD, or
# -3 HEAD. Without any, the commit at HEAD alone is built. A range whose
# start the clone lacks, as after a force push, builds its end alone.
# Uncommitted tracked changes are refused. Each commit builds in a fresh
# temporary worktree.

set -eu

cd "$(git rev-parse --show-toplevel)"

if [ $# -eq 0 ]; then
	set -- -1 HEAD
fi
case $1 in
*..*)
	if [ $# -eq 1 ] && ! git cat-file -e "${1%%..*}^{commit}" 2>/dev/null; then
		printf 'build-commits: no %s here; building %s alone\n' \
			"${1%%..*}" "${1#*..}" >&2
		set -- -1 "${1#*..}"
	fi
	;;
esac

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	printf 'build-commits: the tree has uncommitted changes; commit or stash them first\n' >&2
	exit 2
fi

# A staged kernel artifact is a build input from the caller's checkout.
btf=$PWD/artifacts/bpf-next-kernel-debs/vmlinux.btf
if [ "${BPF_VMLINUX_BTF+x}" != x ] && [ -f "$btf" ]; then
	export BPF_VMLINUX_BTF="$btf"
fi

describe() {
	git log -1 --format='%h ("%s")' "$1"
}

commits=$(git rev-list --reverse --no-merges "$@")
n=$(printf '%s\n' "$commits" | grep -c . || :)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/shirudo-build-commits.XXXXXXXXXX")
tree=$work_dir/tree
cleanup() {
	if [ -d "$tree" ]; then
		git worktree remove --force "$tree"
	fi
	rmdir "$work_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

i=0
for c in $commits; do
	i=$((i + 1))
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::group::[%d/%d] %s\n' "$i" "$n" "$(describe "$c")"
	else
		printf '==== [%d/%d] %s\n' "$i" "$n" "$(describe "$c")"
	fi
	git worktree add --detach --quiet "$tree" "$c"
	if ! (
		cd "$tree" && make -j"$(nproc)" && make shirudo-build &&
		# A commit from before the quote checker has no target for it.
		{ ! grep -q '^quote-check:' Makefile || make quote-check; } &&
		make -C testing test-helpers
	); then
		if [ -n "${GITHUB_ACTIONS:-}" ]; then
			printf '::endgroup::\n'
			printf '::error::%s does not build on its own\n' "$(describe "$c")"
		fi
		printf 'build-commits: %s does not build on its own\n' "$(describe "$c")" >&2
		exit 1
	fi
	git worktree remove --force "$tree"
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::endgroup::\n'
	fi
done

printf 'build-commits: %d commits built\n' "$n"
