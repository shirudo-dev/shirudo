#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-spdx.sh -- verify the SPDX-License-Identifier tags of the
# tracked sources against the licensing rules in AGENTS.md: every source
# file carries a tag in the kernel's form for its type, the expression is
# BSD-2-Clause or GPL-2.0 OR BSD-2-Clause, or the upstream one of a file
# carried from another project, and everything compiled into a BPF
# object, the headers it includes too, and every source a Beefile
# packages carries the dual licence.
#
#   .github/scripts/check-spdx.sh
#
# Runs from anywhere inside the checkout. Vendored C keeps its upstream
# tag, which has to name one of the licences listed in vendor_ok().

set -eu

BSD='BSD-2-Clause'
DUAL='GPL-2.0 OR BSD-2-Clause'

cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

bad=0
checked=0

report() {
	bad=$((bad + 1))
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error file=%s::%s\n' "$1" "$2"
	fi
	printf '%s: %s\n' "$1" "$2" >&2
}

# The kernel's coding-style.rst is carried verbatim and vmlinux.h is
# generated from BTF.
excluded() {
	case "$1" in
	Documentation/contribute/code/coding-style.rst|vmlinux.h|*/vmlinux.h)
		return 0 ;;
	esac
	return 1
}

# The licences vendored C may carry, each one the binaries can take next
# to OpenSSL's Apache-2.0: libbpf's dual licence, the UAPI headers' GPL
# with the syscall note, and shirudo's own shims.
vendor_ok() {
	case "$1" in
	'(LGPL-2.1 OR BSD-2-Clause)'|'BSD-2-Clause'|\
	'GPL-2.0 WITH Linux-syscall-note'|\
	'((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)')
		return 0 ;;
	esac
	return 1
}

# A file carried from another project outside vendor/ keeps its upstream
# tag, which offers the BSD-2-Clause branch shirudo takes it under:
# bpf_map_use_after_delete.cocci comes from tetragon.
carried_ok() {
	case "$1:$2" in
	'testing/coccinelle/bpf_map_use_after_delete.cocci:(GPL-2.0-only OR BSD-2-Clause)')
		return 0 ;;
	esac
	return 1
}

check_vendor() {
	f=$1
	l1=''
	IFS= read -r l1 <"$f" || :
	case "$l1" in
	*SPDX-License-Identifier:*)
		;;
	*)
		report "$f" "vendored without an SPDX-License-Identifier tag on line 1"
		return ;;
	esac
	expr=$(printf '%s' "${l1#*SPDX-License-Identifier:}" |
		sed 's/^[[:space:]]*//; s/[[:space:]]*\*\/[[:space:]]*$//; s/[[:space:]]*$//')
	vendor_ok "$expr" ||
		report "$f" "licence expression '$expr' is not one vendored code may carry"
}

# The comment form of the tag by file type, the kernel's rules with --
# for Lua and .. for reStructuredText. Any other file needs a tag only
# when it starts with a shebang.
kind_of() {
	case "$1" in
	*.c|*.cocci) echo c ;;
	*.h) echo h ;;
	*.lua) echo lua ;;
	*.rst) echo rst ;;
	*.sh|*.bash|*.py|*.in|*.timer|*.service|*.mk)
		echo hash ;;
	Makefile|*/Makefile|Makefile.*|*/Makefile.*)
		echo hash ;;
	*)
		if [ "$(head -c 2 "$1")" = '#!' ]; then
			echo hash
		fi ;;
	esac
}

# The tag sits on the first line, or on the second after a shebang or
# the .. that opens a reStructuredText comment block.
check_file() {
	f=$1
	kind=$2
	l1=''
	l2=''
	{ IFS= read -r l1 || :; IFS= read -r l2 || :; } <"$f"
	want=1
	line=$l1
	case "$kind:$l1" in
	'hash:#!'*|'rst:..')
		want=2
		line=$l2 ;;
	esac

	case "$line" in
	*SPDX-License-Identifier:*)
		;;
	*)
		n=$(head -n 20 "$f" | grep -n -m1 'SPDX-License-Identifier:' |
			cut -d: -f1 || :)
		if [ -n "$n" ]; then
			report "$f" "SPDX tag on line $n, expected on line $want"
		else
			report "$f" "no SPDX-License-Identifier tag on line $want"
		fi
		return ;;
	esac

	expr=${line#*SPDX-License-Identifier:}
	expr=$(printf '%s' "$expr" |
		sed 's/^[[:space:]]*//; s/[[:space:]]*\*\/[[:space:]]*$//; s/[[:space:]]*$//')
	suffix=''
	case "$kind" in
	c)
		prefix='// ' ;;
	h)
		prefix='/* '
		suffix=' */' ;;
	lua)
		prefix='-- ' ;;
	hash)
		prefix='# ' ;;
	rst)
		if [ "$want" -eq 2 ]; then
			prefix=$(printf '%s' "$line" | sed 's/SPDX.*//')
			case "$prefix" in
			*[!\ ]*|'')
				prefix='   ' ;;
			esac
		else
			prefix='.. '
		fi ;;
	esac
	printf '%s\t%s\n' "$f" "$expr" >>"$work/exprs"

	case "$expr" in
	"$BSD"|"$DUAL")
		;;
	*)
		carried_ok "$f" "$expr" || {
			report "$f" "licence expression '$expr' is neither '$BSD' nor '$DUAL'"
			return
		} ;;
	esac
	expected="${prefix}SPDX-License-Identifier: ${expr}${suffix}"
	if [ "$line" != "$expected" ]; then
		report "$f" "the tag of a $kind file reads '$expected', found: $line"
	fi
}

expr_of() {
	awk -F '\t' -v f="$1" '$1 == f { print $2; exit }' "$work/exprs"
}

: >"$work/files"
: >"$work/vendor"
: >"$work/exprs"
git ls-files | while IFS= read -r f; do
	excluded "$f" && continue
	# A tracked symlink points into the tree, where its target is checked.
	[ -L "$f" ] && continue
	case "$f" in
	vendor/*)
		printf '%s\n' "$f" >>"$work/vendor" ;;
	*)
		printf '%s\n' "$f" >>"$work/files" ;;
	esac
done

while IFS= read -r f; do
	kind=$(kind_of "$f")
	[ -n "$kind" ] || continue
	checked=$((checked + 1))
	check_file "$f" "$kind"
done <"$work/files"

# bpf_doc.py writes bpf_helper_defs.h without a tag; it is libbpf's.
while IFS= read -r f; do
	case "$f" in
	vendor/libbpf/bpf/bpf_helper_defs.h)
		continue ;;
	*.c|*.h)
		;;
	*)
		continue ;;
	esac
	checked=$((checked + 1))
	check_vendor "$f"
done <"$work/vendor"

# Everything clang -target bpf compiles, the LSM and its loaders under
# bpf/ and every *.bpf.c, plus the headers they include by relative
# path, found as the build finds them: beside the includer, then in
# bpf/lib. Each line is the file and the file that pulled it in.
grep -E '^bpf/[^/]+\.c$|\.bpf\.c$' "$work/files" |
	sed 's/$/\t/' >"$work/bpf.pending"
: >"$work/bpf.seen"
while [ -s "$work/bpf.pending" ]; do
	: >"$work/bpf.next"
	while IFS='	' read -r f from; do
		grep -qxF "$f" "$work/bpf.seen" && continue
		printf '%s\n' "$f" >>"$work/bpf.seen"
		expr=$(expr_of "$f")
		if [ "$expr" != "$DUAL" ]; then
			report "$f" "compiled into a BPF object${from:+ (included from $from)} but licensed '${expr:-no tag}'; BPF objects carry '$DUAL'"
		fi
		for inc in $(sed -n 's/^[[:space:]]*#[[:space:]]*include[[:space:]]*"\([^"]*\)".*/\1/p' "$f"); do
			for dir in "$(dirname "$f")" bpf/lib; do
				[ -f "$dir/$inc" ] || continue
				cand=$(realpath --relative-to=. "$dir/$inc")
				if grep -qxF "$cand" "$work/files"; then
					printf '%s\t%s\n' "$cand" "$f" >>"$work/bpf.next"
				fi
				break
			done
		done
	done <"$work/bpf.pending"
	mv "$work/bpf.next" "$work/bpf.pending"
done

# A package's sources carry the licence its Beefile declares.
grep -E '(^|/)Beefile$' "$work/files" >"$work/beefiles" || :
while IFS= read -r bee; do
	dir=$(dirname "$bee")
	lic=$(sed -n 's/^license[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$bee" | head -n 1)
	if [ -z "$lic" ]; then
		report "$bee" "no license field"
		continue
	fi
	sed -n 's/^source[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$bee" >"$work/sources"
	while IFS= read -r src; do
		case "$src" in
		*.c|*.h|*.lua) ;;
		*) continue ;;
		esac
		path="$dir/$src"
		expr=$(expr_of "$path")
		if [ "$expr" != "$lic" ]; then
			report "$path" "shipped by $bee under '$lic' but licensed '${expr:-no tag}'"
		fi
	done <"$work/sources"
done <"$work/beefiles"

if [ "$bad" -gt 0 ]; then
	printf '%d SPDX problems in %d files\n' "$bad" "$checked" >&2
	exit 1
fi
printf 'SPDX: %d files checked\n' "$checked"
