#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0009 -- .github/scripts/check-unused.sh: an extern function nothing
# calls fails the check, whichever line its type stands on, while a call
# from another file, a header's inline function or macro, a test or the
# function's own file counts, and static functions, BPF programs, entry
# points and linker wrappers are not its business; on a throwaway
# repository, and the tree itself.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-unused.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/repo

# A file with the given lines, each argument one line.
put() {
	f=$R/$1
	shift
	mkdir -p "$(dirname "$f")"
	printf '%s\n' "$@" >"$f"
}

# A tree the check passes: every extern function has a caller of one kind.
good() {
	rm -rf "$R" && mkdir -p "$R" && git init -q "$R" &&
	put util/a.h 'int called(void);' 'int inlined(void);' \
		'int by_macro(void);' 'int by_test(void);' \
		'static inline int wrap(void)' '{' '	return inlined();' '}' \
		'#define BY_MACRO() by_macro()' &&
	put util/a.c '#include "a.h"' '' \
		'static int helper(void)' '{' '	return 0;' '}' '' \
		'int called(void)' '{' '	return helper();' '}' '' \
		'int inlined(void)' '{' '	return 1;' '}' '' \
		'int' 'by_macro(void)' '{' '	return 2;' '}' '' \
		'int by_test(void)' '{' '	return 3;' '}' '' \
		'int local(void)' '{' '	return 4;' '}' '' \
		'int local_user(void)' '{' '	return local() + wrap() + BY_MACRO();' '}' &&
	put util/b.c '#include "a.h"' '' \
		'int main(void)' '{' '	return called() + local_user();' '}' &&
	put testing/unit/a.c '#include "a.h"' '' \
		'static void case_one(void)' '{' '	by_test();' '}' &&
	put testing/helper/fault.c 'int __wrap_Esys_Startup(void)' '{' \
		'	return 0;' '}' &&
	put bpf/prog.c 'int prog_entry(void *ctx)' '{' '	return 0;' '}'
}

check() {
	(cd "$R" && git add -A && sh "$S") >"$W/out" 2>"$W/err"
}

# The check fails and says so.
refuses() {
	! check && grep -qF "$1" "$W/err"
}

test_expect_success 'a tree whose extern functions all have a caller passes' '
	good && check
'

test_expect_success 'an extern function nothing calls is refused' '
	good && put util/c.c "int orphan(const char *s)" "{" "	return !s;" "}" &&
	refuses "util/c.c:1: orphan() is defined, but nothing calls it"
'

test_expect_success 'one whose type stands on the line above is refused too' '
	good && put util/c.c "unsigned long" "orphan(void)" "{" "	return 0;" "}" &&
	refuses "util/c.c:2: orphan() is defined, but nothing calls it"
'

test_expect_success 'a declaration in a header is no call' '
	good && put util/c.c "int orphan(void)" "{" "	return 0;" "}" &&
	put util/c.h "int orphan(void);" &&
	refuses "orphan() is defined, but nothing calls it"
'

test_expect_success 'a prototype in a C file is no definition' '
	good && put util/c.c "int later(void);" &&
	check
'

if [ "${SHIRUDO_SKIP_TREE_CHECKS:-0}" != 1 ]; then
	test_expect_success 'the tree itself passes' '
		sh "$S"
	'
fi

test_done
