#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
# shellcheck disable=SC2016,SC2329 # test_expect_success evaluates the body.

cd "$(dirname "$0")/.." || exit 1
# shellcheck source=testing/test-lib.sh
. ./test-lib.sh
for tool in git make; do
	command -v "$tool" >/dev/null 2>&1 || test_skip_all "$tool is required"
done

checker=$(cd .. && pwd)/.github/scripts/build-commits.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
repo=$fixture/repo
scratch=$fixture/scratch
mkdir -p "$fixture/bin" "$scratch" "$repo/testing" \
	"$repo/artifacts/bpf-next-kernel-debs"
printf '#!/bin/sh\nprintf "1\\n"\n' >"$fixture/bin/nproc"
chmod +x "$fixture/bin/nproc"
printf '/generated.txt\n/artifacts/\n' >"$repo/.gitignore"
printf 'fixture BTF\n' >"$repo/artifacts/bpf-next-kernel-debs/vmlinux.btf"
cat >"$repo/Makefile" <<'EOF'
BPF_VMLINUX_BTF ?= artifacts/bpf-next-kernel-debs/vmlinux.btf
all: generated.txt
	@test -s generated.txt
	@grep -qxF 'fixture BTF' "$(BPF_VMLINUX_BTF)"
shirudo-build:
	@test -s generated.txt
quote-check:
	@test -s generated.txt
-include generator.mk
EOF
printf 'generated.txt:\n\t@echo generated >$@\n' >"$repo/generator.mk"
printf 'test-helpers:\n\t@test -s ../generated.txt\n' >"$repo/testing/Makefile"

export GIT_AUTHOR_NAME='Fixture Author' GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=$GIT_AUTHOR_NAME GIT_COMMITTER_EMAIL=$GIT_AUTHOR_EMAIL
git init -q -b fixture "$repo"
git -C "$repo" config commit.gpgsign false
git -C "$repo" config core.hooksPath /dev/null
git -C "$repo" add .
git -C "$repo" commit -qm 'generate the build input'
first=$(git -C "$repo" rev-parse HEAD)
git -C "$repo" rm -q generator.mk
git -C "$repo" commit -qm 'require the input without generating it'
second=$(git -C "$repo" rev-parse HEAD)

run() {
	(cd "$repo" && env -u GITHUB_ACTIONS -u BPF_VMLINUX_BTF -u MAKEFLAGS \
		TMPDIR="$scratch" PATH="$fixture/bin:$PATH" sh "$checker" "$@") \
		>"$fixture/out" 2>"$fixture/err" || {
		ret=$?
		cat "$fixture/err" >&2
		return "$ret"
	}
}

clean() {
	[ "$(git -C "$repo" symbolic-ref --short HEAD)" = fixture ] &&
	[ "$(git -C "$repo" rev-parse HEAD)" = "$second" ] &&
	[ "$(git -C "$repo" worktree list --porcelain | grep -c '^worktree ')" = 1 ] &&
	[ -z "$(find "$scratch" -name 'shirudo-build-commits.*' -print)" ]
}

expect_build_failure() {
	status=0
	run "$@" || status=$?
	[ "$status" = 1 ] &&
	grep -F "does not build on its own" "$fixture/err"
}

test_expect_success 'fail a commit that needs an earlier build output' '
	expect_build_failure -2 "$second" &&
	grep -F "require the input without generating it" "$fixture/err" &&
	clean
'

printf 'local output\n' >"$repo/generated.txt"
test_expect_success 'leave existing build output in the original checkout' '
	expect_build_failure &&
	grep -qxF "local output" "$repo/generated.txt" &&
	clean
'

test_expect_success 'build a self-contained commit using the staged BTF' '
	run -1 "$first" &&
	grep -qxF "build-commits: 1 commits built" "$fixture/out" &&
	grep -qxF "local output" "$repo/generated.txt" &&
	clean
'

test_done
