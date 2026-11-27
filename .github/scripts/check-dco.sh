#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-dco.sh -- verify that every commit in a range has
# the message Documentation/contribute/code/contributing.rst asks for: a
# one-line subject, a body that says more than its tags, and the
# Signed-off-by of its author, the Developer's Certificate of Origin, from
# an identity a person answers at: a noreply address or a bot is no
# identity, as author, signer or co-developer, except for Dependabot's
# canonical author and sign-off identity, and neither is a handle or a
# given name alone. Merge commits are skipped.
#
#   .github/scripts/check-dco.sh [<rev-list arguments>]
#
# The arguments go to git rev-list: a range such as origin/main..HEAD,
# or -3 HEAD. Without any, the commit at HEAD alone is checked.

set -eu

if [ $# -eq 0 ]; then
	set -- -1 HEAD
fi

bad=0
checked=0

report() {
	failed=1
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error::%s\n' "$*"
	fi
	printf 'error: %s\n' "$*" >&2
}

lower() {
	printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# The noreply addresses GitHub and the coding agents write with, and
# anything called [bot], can neither be reached nor certify the DCO.
impersonal() {
	case "$(lower "$1")" in
	*noreply*|*no-reply*|*'[bot]'*)
		return 0
		;;
	esac
	return 1
}

dependabot_identity() {
	printf '%s\n' "$(lower "$1")" |
		grep -Eq '^dependabot\[bot\] <[0-9]+\+dependabot\[bot\]@users\.noreply\.github\.com>$'
}

dependabot_signoff() {
	[ "$(lower "$1")" = 'dependabot[bot] <support@github.com>' ]
}

# The bytes outside ASCII, which the check takes for letters: no locale
# tells the letters of every script apart, so it reads ASCII alone.
high=$(printf '\200-\377')
full="(a given name and a surname, capitalized, in letters)"

# A known identity names the person: two words or more, a given name
# and a surname, made of letters, with a hyphen, an apostrophe or a
# period inside. The first word and the last carry a capital, so a name
# keeps its particles but not a handle in lowercase. A name in a script
# without case, as Chinese is written, can be one word.
full_name() {
	printf '%s\n' "$1" | LC_ALL=C grep -Eq "^[A-Za-z .'$high-]+\$" ||
		return 1
	# shellcheck disable=SC2086 # one word per line, no glob left to expand
	words=$(printf '%s\n' $1)
	printf '%s\n' "$words" | LC_ALL=C grep -vq "[A-Za-z$high]" &&
		return 1
	printf '%s\n' "$1" | LC_ALL=C grep -q '[A-Za-z]' || return 0
	[ "$(printf '%s\n' "$words" | LC_ALL=C grep -c .)" -ge 2 ] || return 1
	! printf '%s\n' "$words" | sed -n '1p; $p' | LC_ALL=C grep -q '^[a-z][^A-Z]*$'
}

commits=$(git rev-list --no-merges "$@")

for commit in $commits; do
	checked=$((checked + 1))
	failed=0
	id=$(git log -1 --format='%h ("%s")' "$commit")
	author=$(git log -1 --format='%an <%ae>' "$commit")
	message=$(git log -1 --format=%B "$commit")
	signoffs=$(printf '%s\n' "$message" | grep -i '^signed-off-by:' || :)
	codevs=$(printf '%s\n' "$message" | grep -i '^co-developed-by:' || :)

	if impersonal "$author" && ! dependabot_identity "$author"; then
		report "$id: the author is a noreply or bot identity, not a person: $author"
		bad=$((bad + 1))
		continue
	fi
	if ! dependabot_identity "$author" && ! full_name "${author% <*}"; then
		report "$id: the author is not named in full $full: $author"
		bad=$((bad + 1))
		continue
	fi

	# The subject is the first paragraph and one line; the body follows
	# the blank line after it, and tag lines alone do not make one.
	nsubject=$(printf '%s\n' "$message" | sed '/^[[:space:]]*$/q' | grep -c . || :)
	body=$(printf '%s\n' "$message" | sed '1,/^[[:space:]]*$/d' |
		grep -Ev '^[[:space:]]*$|^[A-Za-z][A-Za-z0-9-]*:[[:space:]]' || :)
	if [ "$nsubject" -eq 0 ]; then
		report "$id: empty commit message"
		bad=$((bad + 1))
		continue
	fi
	if [ "$nsubject" -gt 1 ]; then
		report "$id: the subject runs on for $nsubject lines; one line, a blank line, then the body"
		bad=$((bad + 1))
		continue
	fi
	if [ -z "$body" ]; then
		report "$id: no body text; a subject and tags alone do not say why the change is made"
		bad=$((bad + 1))
		continue
	fi
	if [ -z "$signoffs" ]; then
		report "$id: no Signed-off-by: line; sign the commit with git commit -s"
		bad=$((bad + 1))
		continue
	fi

	# One finding per commit: the first ill-formed sign-off line, else
	# the absence of the author's.
	problem=''
	by_author=0
	while IFS= read -r line; do
		value=$(printf '%s' "$line" |
			sed 's/^[Ss][Ii][Gg][Nn][Ee][Dd]-[Oo][Ff][Ff]-[Bb][Yy]:[[:space:]]*//; s/[[:space:]]*$//')
		if [ "$(lower "$value")" = "$(lower "$author")" ] ||
		   { dependabot_identity "$author" && dependabot_signoff "$value"; }; then
			by_author=1
		fi
		[ -z "$problem" ] || continue
		case "$line" in
		'Signed-off-by: '*)
			;;
		*)
			problem="the tag is spelled 'Signed-off-by: ', found: $line"
			continue
			;;
		esac
		# A name and an address in angle brackets, as git commit -s
		# writes them; an address alone or a name alone is no identity.
		if ! printf '%s\n' "$value" |
		   grep -Eq '^[^<>]*[^<>[:space:]][^<>]* <[^<>@[:space:]]+@[^<>@[:space:]]+>$'; then
			problem="malformed sign-off, expected 'Name <email>', found: $line"
		elif impersonal "$value" &&
		     { ! dependabot_identity "$author" || ! dependabot_signoff "$value"; }; then
			problem="a noreply or bot identity cannot certify the DCO: $line"
		elif ! dependabot_signoff "$value" && ! full_name "${value% <*}"; then
			problem="a sign-off is not a full name $full: $line"
		fi
	done <<EOT
$signoffs
EOT

	# A co-developer is an author too.
	if [ -z "$problem" ] && [ -n "$codevs" ]; then
		while IFS= read -r line; do
			value=$(printf '%s' "${line#*:}" |
				sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
			if impersonal "$value"; then
				problem="a noreply or bot identity cannot be a co-developer: $line"
				break
			fi
			if ! full_name "${value% <*}"; then
				problem="a co-developer is not named in full $full: $line"
				break
			fi
		done <<EOT
$codevs
EOT
	fi

	if [ -n "$problem" ]; then
		report "$id: $problem"
	elif [ "$by_author" -eq 0 ]; then
		found=$(printf '%s\n' "$signoffs" | sed 's/^[Ss]igned-off-by:[[:space:]]*//' |
			tr '\n' ',' | sed 's/,$//; s/,/, /g')
		report "$id: no sign-off by the author, expected 'Signed-off-by: $author', found: $found"
	fi
	if [ "$failed" -ne 0 ]; then
		bad=$((bad + 1))
	fi
done

if [ "$bad" -gt 0 ]; then
	printf '%d of %d commits fail the DCO check\n' "$bad" "$checked" >&2
	exit 1
fi
printf 'DCO: %d commits checked\n' "$checked"
