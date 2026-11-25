#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-docs.sh -- check Documentation/ against the tree:
# every option a console example passes to shirudo exists in a parser,
# every failure category the code emits, every tamper and integrity
# counter and every proof has its entry in the reference, every hook,
# counter, test, proof and unit a page names exists, every LSM program
# and counter stands in the fact box of a threat, every source file is
# read by a proof or listed as read by none, and every figure is what its
# TikZ source makes.
#
#   .github/scripts/check-docs.sh
#
# Runs from anywhere inside the checkout.

set -eu

cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Loops on the right of a pipe run in subshells, so findings go to a file.
report() {
	printf '%s: %s\n' "$1" "$2" >>"$work/errors"
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error file=%s::%s\n' "$1" "$2"
	fi
	printf '%s: %s\n' "$1" "$2" >&2
}

find Documentation -name '*.rst' -not -path 'Documentation/output*' \
	-not -path 'Documentation/contribute/code/coding-style.rst' | sort >"$work/pages"

# The options of the command lines in console blocks, by page. A command
# line ending in a backslash is joined to the next, as the shell does,
# and so is one with blanks after the backslash, which a reader pastes
# all the same. Only a command is joined: a backslash that ends any
# other line of a page would take the prompt of the next one with it,
# and a command ends at the next prompt or blank line whatever it ends
# in, as that one starts another.
while IFS= read -r page; do
	awk '
	joined && /^[ \t]*$|^[ \t]+(operator\$|target#|\$|#) / {
		print ""
		joined = 0
	}
	!joined && !/^[ \t]+(operator\$|target#|\$|#) shirudo( |$)/ { next }
	{
		joined = sub(/\\[ \t]*$/, "")
		printf "%s%s", $0, joined ? "" : "\n"
	}
	END { if (joined) print "" }' "$page" |
		grep -oE -- '--[a-z0-9][a-z0-9-]*' | sort -u |
		sed "s|^|$page |"
done <"$work/pages" >"$work/options"

cat shirudo.c builtin-*.c tools/shirudo-build/*.c tools/gen-image/* \
	tools/gen-initrd/* >"$work/parsers"
while read -r page option; do
	grep -qF -- "\"$option" "$work/parsers" ||
		grep -qE -- "(^|[^a-z0-9-])$option([^a-z0-9-]|\$)" \
			tools/gen-image/* tools/gen-initrd/* ||
		report "$page" "no parser accepts $option"
done <"$work/options"

# Every failure category the code emits has an entry.
categories=Documentation/reference/failure-categories.rst
{
	grep -ohE 'rep_fail\([^,]+, "[a-z_]+", "[a-z_]+"' builtin-*.c util/*.c |
		sed -E 's/.*"([a-z_]+)"$/\1/'
	grep -ohE '(cat|category) = "[a-z_]+"' builtin-*.c util/*.c |
		sed -E 's/.*"([a-z_]+)"$/\1/'
	sed -n '/^static const char \*cat_from_load_errno/,/^}/p' builtin-upatch.c |
		grep -oE 'return "[a-z_]+"' | sed -E 's/.*"([a-z_]+)"$/\1/'
} | sort -u >"$work/categories"
while IFS= read -r category; do
	grep -qF "\`\`$category\`\`" "$categories" ||
		report "$categories" "no entry for the emitted category $category"
done <"$work/categories"

# Every tamper and integrity counter has an entry on its page, and a
# page names no other.
counter_names() {
	grep -oE '= \{ "[A-Za-z]+",' "$1" | sed -E 's/.*"([A-Za-z]+)".*/\1/' |
		sort -u
}
counter_names util/tamper.c >"$work/tamper_counters"
counter_names util/integrity.c >"$work/integrity_counters"
sort -u "$work/tamper_counters" "$work/integrity_counters" >"$work/counters"
for kind in tamper integrity; do
	counters=Documentation/security/$kind-counters.rst
	while IFS= read -r counter; do
		grep -qF "\`\`$counter\`\`" "$counters" ||
			report "$counters" "no entry for the counter $counter"
	done <"$work/${kind}_counters"
done

# A field of a fact box, with the lines that continue it, as one line.
field() {
	awk -v name=":$1:" '
		index($0, name) == 1 { on = 1; printf "%s", $0; next }
		on && /^[ \t]+[^ \t]/ { printf " %s", $0; next }
		on { print ""; on = 0 }
		END { if (on) print "" }' "$2"
}

# The hooks and counters a threat fact box names exist. A hook is named
# by its section, which says whether the program is sleepable.
grep -ohE 'SEC\("lsm(\.s)?/[a-z_]+"\)' bpf/*.c bpf/lib/*.h |
	sed -E 's/SEC\("(.*)"\)/\1/' | sort -u >"$work/hooks"
while IFS= read -r page; do
	field 'Enforced at' "$page" | grep -oE '``lsm(\.s)?/[a-z_]+``' |
		tr -d '`' | sort -u | while IFS= read -r hook; do
		grep -qxF "$hook" "$work/hooks" ||
			report "$page" "no BPF program has the section $hook"
	done
	field Counters "$page" | grep -oE '``[A-Za-z]+``' |
		tr -d '`' | sort -u | while IFS= read -r counter; do
		grep -qx "$counter" "$work/counters" ||
			report "$page" "no counter is named $counter"
	done
done <"$work/pages"

# Every LSM program and every counter stands in the fact box of some
# threat. A page without one is no error of the loop.
threats=Documentation/security/threat-model.rst
while IFS= read -r page; do
	field 'Enforced at' "$page" | grep -oE '``lsm(\.s)?/[a-z_]+``' || :
done <"$work/pages" | tr -d '`' | sort -u >"$work/named_hooks"
while IFS= read -r hook; do
	grep -qxF "$hook" "$work/named_hooks" ||
		report "$threats" "no threat names the program $hook"
done <"$work/hooks"
while IFS= read -r page; do
	field Counters "$page" | grep -oE '``[A-Za-z]+``' || :
done <"$work/pages" | tr -d '`' | sort -u >"$work/named_counters"
while IFS= read -r counter; do
	grep -qx "$counter" "$work/named_counters" ||
		report "$threats" "no threat names the counter $counter"
done <"$work/counters"

# Every test id a page names exists under testing/.
find testing -name 't[0-9][0-9][0-9][0-9]-*' | sed -E 's|.*/(t[0-9]{4}).*|\1|' |
	sort -u >"$work/tests"
while IFS= read -r page; do
	grep -oE '``t[0-9]{4}[a-z0-9-]*``' "$page" | tr -d '`' | cut -c1-5 |
		sort -u | while IFS= read -r test; do
		grep -qx "$test" "$work/tests" ||
			report "$page" "no test is numbered $test"
	done
done <"$work/pages"

# Every proof has a row on the coverage page, and a fact box names only
# proofs that exist.
coverage=Documentation/contribute/testing/proof-coverage.rst
grep -v '^[[:space:]]*\(#\|$\)' testing/proofs/cbmc/proofs.list |
	awk '{ print $1 }' >"$work/proofs"
for model in testing/proofs/lean4/Shirudo/*.lean; do
	model=${model##*/}
	printf 'Shirudo.%s\n' "${model%.lean}"
done >>"$work/proofs"
while IFS= read -r proof; do
	grep -qF "* - \`\`$proof\`\`" "$coverage" ||
		report "$coverage" "no row for the proof $proof"
done <"$work/proofs"
while IFS= read -r page; do
	field Proofs "$page" | grep -oE '``[A-Za-z0-9.-]+``' | tr -d '`' |
		sort -u | while IFS= read -r proof; do
		grep -qx "$proof" "$work/proofs" ||
			report "$page" "no proof is named $proof"
	done
done <"$work/pages"

# The tree files a harness includes, through another harness too.
harness_reads() {
	grep -oE '^#include "[^"]+"' "$1" | sed -E 's/^#include "(.*)"$/\1/' |
		while IFS= read -r inc; do
		case $inc in
		../../../*) printf '%s\n' "${inc#../../../}" ;;
		proof.h) ;;
		*)
			[ ! -e "testing/proofs/cbmc/$inc" ] ||
				harness_reads "testing/proofs/cbmc/$inc"
			;;
		esac
	done
}

# Every source file is read by a harness or listed on the coverage page
# as read by none, and no file is both.
for harness in testing/proofs/cbmc/*.c; do
	harness_reads "$harness"
done | sort -u >"$work/read"
sed -n '/^Files without a proof$/,/^Not covered yet$/p' "$coverage" |
	grep -oE ':src:`[^`]+\.c`' | sed -E 's/:src:`(.*)`/\1/' |
	sort -u >"$work/unread"
git ls-files 'util/*.c' 'builtin-*.c' shirudo.c 'tools/shirudo-build/*.c' |
	sort >"$work/sources"
while IFS= read -r source; do
	grep -qxF "$source" "$work/read" || grep -qxF "$source" "$work/unread" ||
		report "$coverage" "no proof reads $source and no line says why"
done <"$work/sources"
while IFS= read -r source; do
	grep -qxF "$source" "$work/sources" ||
		report "$coverage" "no source file is named $source"
	! grep -qxF "$source" "$work/read" ||
		report "$coverage" "a proof reads $source, which the page lists as read by none"
done <"$work/unread"

# Every unit a page names exists under systemd/.
while IFS= read -r page; do
	grep -oE 'shirudo(-[a-z0-9]+)*\.(service|timer)' "$page" | sort -u |
		while IFS= read -r unit; do
		[ -e "systemd/$unit" ] || [ -e "systemd/$unit.in" ] ||
			report "$page" "no unit is named $unit"
	done
done <"$work/pages"

# Every figure of Documentation/images/ is what its TikZ source makes,
# which build.py tells from the hash it recorded, without TeX. A tree
# without the script has no figures to check.
if [ -f Documentation/figures/build.py ] &&
   ! python3 Documentation/figures/build.py --check 2>"$work/figures"; then
	while IFS= read -r line; do
		report Documentation/figures "${line#figures: }"
	done <"$work/figures"
fi

printf 'docs: %s pages checked\n' "$(wc -l <"$work/pages")"
[ ! -s "$work/errors" ]
