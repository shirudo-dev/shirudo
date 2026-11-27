#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0001 -- .github/scripts/check-dco.sh: the subject, body and sign-off every
# commit needs, the forms it rejects, the full names it wants, the author
# the sign-off must come from and the merge commits it skips, on a
# throwaway repository.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
S=$(cd .. && pwd)/.github/scripts/check-dco.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/repo
export GIT_AUTHOR_NAME='Random J Developer' GIT_AUTHOR_EMAIL='random@developer.example.org'
export GIT_COMMITTER_NAME='Random J Developer' GIT_COMMITTER_EMAIL='random@developer.example.org'
git init -q "$R"
git -C "$R" config commit.gpgsign false

commit() {
	msg=$1
	shift
	git -C "$R" commit -q --allow-empty -m "$msg" "$@"
}

check() {
	(cd "$R" && sh "$S" "$@") >"$W/out" 2>"$W/err"
}

test_expect_success 'a commit with a subject, a body and the author sign-off passes' '
	commit "a: first

Why the change is made." -s &&
	check &&
	grep -q "DCO: 1 commits checked" "$W/out"
'

test_expect_success 'a commit without a sign-off fails' '
	commit "a: unsigned

Why the change is made." &&
	! check &&
	grep -q "no Signed-off-by: line" "$W/err" &&
	grep -q "1 of 1 commits fail" "$W/err"
'

test_expect_success 'a sign-off by someone else is not the author'"'"'s' '
	commit "a: someone else

Why the change is made.

Signed-off-by: Other Person <other@example.org>" &&
	! check &&
	grep -q "no sign-off by the author, expected .Signed-off-by: Random J Developer <random@developer.example.org>., found: Other Person <other@example.org>" "$W/err"
'

test_expect_success 'a sign-off without an address is malformed' '
	commit "a: no address

Why the change is made.

Signed-off-by: Random J Developer" &&
	! check &&
	grep -q "malformed sign-off" "$W/err"
'

test_expect_success 'a sign-off with an address alone is malformed' '
	commit "a: no name

Why the change is made.

Signed-off-by: <random@developer.example.org>" &&
	! check &&
	grep -q "malformed sign-off" "$W/err"
'

test_expect_success 'the tag keeps its spelling' '
	commit "a: spelling

Why the change is made.

signed-off-by: Random J Developer <random@developer.example.org>" &&
	! check &&
	grep -q "spelled .Signed-off-by: ." "$W/err"
'

test_expect_success 'the identity compares without case' '
	commit "a: case

Why the change is made.

Signed-off-by: RANDOM J DEVELOPER <Random@Developer.Example.Org>" &&
	check
'

test_expect_success 'the author sign-off counts among several' '
	commit "a: chain

Why the change is made.

Co-developed-by: Other Person <other@example.org>
Signed-off-by: Other Person <other@example.org>
Signed-off-by: Random J Developer <random@developer.example.org>" &&
	check
'

test_expect_success 'an empty message fails' '
	commit "" --allow-empty-message &&
	! check &&
	grep -q "empty commit message" "$W/err"
'

test_expect_success 'a subject with the sign-off alone has no body' '
	commit "a: bare" -s &&
	! check &&
	grep -q "no body text" "$W/err"
'

test_expect_success 'tags alone do not make a body' '
	commit "a: tags only

Fixes: 1234567890ab (\"a: earlier\")
Link: https://example.org/report
Signed-off-by: Random J Developer <random@developer.example.org>" &&
	! check &&
	grep -q "no body text" "$W/err"
'

test_expect_success 'a subject running into the body is not a subject' '
	commit "a: glued
Why the change is made.
Signed-off-by: Random J Developer <random@developer.example.org>" &&
	! check &&
	grep -q "the subject runs on for 3 lines" "$W/err"
'

test_expect_success 'a range reports every failing commit once' '
	! check -12 HEAD &&
	[ "$(grep -c "^error:" "$W/err")" -eq 9 ] &&
	grep -q "9 of 12 commits fail" "$W/err"
'

test_expect_success 'Dependabot author and sign-off are accepted' '
	commit "a: Dependabot update

Why the change is made.

Signed-off-by: dependabot[bot] <support@github.com>" \
		--author="dependabot[bot] <123456789+dependabot[bot]@users.noreply.github.com>" &&
	check &&
	grep -q "DCO: 1 commits checked" "$W/out"
'

test_expect_success 'Dependabot cannot sign a human-authored commit' '
	commit "a: bot sign-off

Why the change is made.

Signed-off-by: Random J Developer <random@developer.example.org>
Signed-off-by: dependabot[bot] <support@github.com>" &&
	! check &&
	grep -q "cannot certify the DCO: Signed-off-by: dependabot\[bot\]" "$W/err"
'

test_expect_success 'merge commits are skipped' '
	base=$(git -C "$R" rev-parse HEAD) &&
	git -C "$R" checkout -q -b side &&
	commit "b: side

Why the change is made." -s &&
	git -C "$R" checkout -q - &&
	commit "a: mainline

Why the change is made." -s &&
	git -C "$R" merge -q --no-ff -m "Merge branch side" side &&
	check "$base..HEAD" &&
	grep -q "DCO: 2 commits checked" "$W/out"
'

test_expect_success 'a bot is not an author' '
	commit "a: bot author

Why the change is made.

Signed-off-by: helper[bot] <helper@bots.example.org>" \
		--author="helper[bot] <helper@bots.example.org>" &&
	! check &&
	grep -q "the author is a noreply or bot identity, not a person: helper\[bot\] <helper@bots.example.org>" "$W/err"
'

test_expect_success 'a noreply sign-off cannot certify the DCO' '
	commit "a: noreply sign-off

Why the change is made.

Signed-off-by: Random J Developer <random@developer.example.org>
Signed-off-by: Some Agent <noreply@agent.example.org>" &&
	! check &&
	grep -q "cannot certify the DCO: Signed-off-by: Some Agent <noreply@agent.example.org>" "$W/err"
'

test_expect_success 'a GitHub privacy address is no identity either' '
	commit "a: privacy address

Why the change is made.

Signed-off-by: Random J Developer <12345+random@users.noreply.github.com>" \
		--author="Random J Developer <12345+random@users.noreply.github.com>" &&
	! check &&
	grep -q "the author is a noreply or bot identity" "$W/err"
'

test_expect_success 'a noreply co-developer is rejected' '
	commit "a: noreply co-developer

Why the change is made.

Co-developed-by: Some Agent <noreply@agent.example.org>
Signed-off-by: Random J Developer <random@developer.example.org>" &&
	! check &&
	grep -q "cannot be a co-developer: Co-developed-by: Some Agent <noreply@agent.example.org>" "$W/err"
'

test_expect_success 'a handle is no name' '
	commit "a: handle

Why the change is made.

Signed-off-by: rjdev <random@developer.example.org>" \
		--author="rjdev <random@developer.example.org>" &&
	! check &&
	grep -q "the author is not named in full (a given name and a surname, capitalized, in letters): rjdev <random@developer.example.org>" "$W/err"
'

test_expect_success 'a given name alone is no full name' '
	commit "a: given name

Why the change is made.

Signed-off-by: Random <random@developer.example.org>" \
		--author="Random <random@developer.example.org>" &&
	! check &&
	grep -q "the author is not named in full" "$W/err"
'

test_expect_success 'a name in lowercase is a handle' '
	commit "a: lowercase

Why the change is made.

Signed-off-by: random developer <random@developer.example.org>" \
		--author="random developer <random@developer.example.org>" &&
	! check &&
	grep -q "the author is not named in full" "$W/err"
'

test_expect_success 'a name with a digit is a handle' '
	commit "a: digit

Why the change is made.

Signed-off-by: Random Developer2 <random@developer.example.org>" \
		--author="Random Developer2 <random@developer.example.org>" &&
	! check &&
	grep -q "the author is not named in full" "$W/err"
'

test_expect_success 'every sign-off names a person in full' '
	commit "a: maintainer handle

Why the change is made.

Signed-off-by: Random J Developer <random@developer.example.org>
Signed-off-by: maint <maintainer@example.org>" &&
	! check &&
	grep -q "a sign-off is not a full name (a given name and a surname, capitalized, in letters): Signed-off-by: maint <maintainer@example.org>" "$W/err"
'

test_expect_success 'a co-developer is named in full' '
	commit "a: co-developer handle

Why the change is made.

Co-developed-by: other <other@example.org>
Signed-off-by: Other Person <other@example.org>
Signed-off-by: Random J Developer <random@developer.example.org>" &&
	! check &&
	grep -q "a co-developer is not named in full (a given name and a surname, capitalized, in letters): Co-developed-by: other <other@example.org>" "$W/err"
'

test_expect_success 'particles, hyphens, apostrophes and initials make a name' '
	commit "a: particles

Why the change is made.

Co-developed-by: Jean-Random O'"'"'Other <other@example.org>
Signed-off-by: Jean-Random O'"'"'Other <other@example.org>
Signed-off-by: Random J. van der Developer <random@developer.example.org>" \
		--author="Random J. van der Developer <random@developer.example.org>" &&
	check
'

test_expect_success 'a name outside ASCII is a name' '
	name=$(printf "Zo\303\253 \303\205ngstr\303\266m") &&
	commit "a: accents

Why the change is made.

Signed-off-by: $name <random@developer.example.org>" \
		--author="$name <random@developer.example.org>" &&
	check
'

test_expect_success 'a name in a script without case can be one word' '
	name=$(printf "\347\216\213\345\260\217\346\230\216") &&
	commit "a: one word

Why the change is made.

Signed-off-by: $name <random@developer.example.org>" \
		--author="$name <random@developer.example.org>" &&
	check
'

test_expect_success 'an unknown range fails' '
	! check nonexistent..HEAD
'

test_done
