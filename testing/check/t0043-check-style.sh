#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0043 -- .github/scripts/check-style.sh: the kernel style checkpatch.pl
# enforces on the C a commit touches at 100 columns, the block-comment
# opener and the subject length the wrapper adds, the message of a commit
# that touches no C, the sources it leaves alone, the userspace spellings
# it lets through, the C library's integer names, number parsers and
# string copies it refuses and the list of what stays enabled, on a
# throwaway repository.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
command -v perl >/dev/null 2>&1 || test_skip_all "perl not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-style.sh
# The kernel's checkpatch.pl is fetched on first use; the test runs
# against a copy already at hand, never the network.
: "${CHECKPATCH:=$ROOT/build/checkpatch/checkpatch.pl}"
[ -r "$CHECKPATCH" ] ||
	test_skip_all "no checkpatch.pl at hand; run check-style.sh once or set CHECKPATCH"
export CHECKPATCH
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/repo
export GIT_AUTHOR_NAME='Random J Developer' GIT_AUTHOR_EMAIL='random@developer.example.org'
export GIT_COMMITTER_NAME='Random J Developer' GIT_COMMITTER_EMAIL='random@developer.example.org'
git init -q "$R"
git -C "$R" config commit.gpgsign false

# A file with the given lines, each argument one line.
put() {
	f=$R/$1
	shift
	mkdir -p "$(dirname "$f")"
	printf '%s\n' "$@" >"$f"
}

commit() {
	git -C "$R" add -A && git -C "$R" commit -q -m "$1" -s
}

# Under GitHub Actions the checker prefixes each finding for the runner;
# the tests look at the plain form, and at the prefixed one once.
check() {
	(cd "$R" && GITHUB_ACTIONS= sh "$S" "$@") >"$W/out" 2>"$W/err"
}

test_expect_success 'kernel-style C with the SPDX tag of each file type passes' '
	put good.c "// SPDX-License-Identifier: BSD-2-Clause" \
		"/*" " * Copyright (c) 2026 Authors of shirudo" " */" "" \
		"#include \"good.h\"" "" \
		"int good(int x)" "{" \
		"	/*" "	 * The sum, with a comment that runs on" \
		"	 * to a second line." "	 */" \
		"	return x + 1; /* trailing */" "}" &&
	put good.h "/* SPDX-License-Identifier: BSD-2-Clause */" \
		"#ifndef GOOD_H" "#define GOOD_H" "" "int good(int x);" "" \
		"#endif /* GOOD_H */" &&
	commit "a: add good

Why the change is made." &&
	check &&
	grep -q "style: 1 commits checked" "$W/out"
'

test_expect_success 'a // comment is an error' '
	put bad.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"int bad(int x)" "{" "	return x; // the C99 way" "}" &&
	commit "a: add bad

Why the change is made." &&
	! check &&
	grep -q "^ERROR:C99_COMMENTS" "$W/out" &&
	grep -q "1 of 1 commits have style problems" "$W/err"
'

test_expect_success 'a block comment opening with text on the /* line is an error' '
	put netdev.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"/* The netdev form puts text here" " * and goes on." " */" \
		"int netdev(int x)" "{" "	return x;" "}" &&
	commit "a: add netdev

Why the change is made." &&
	! check &&
	grep -q "^ERROR:NETDEV_BLOCK_COMMENT" "$W/out" &&
	grep -q "FILE: netdev.c:3:" "$W/out"
'

test_expect_success 'a line of 100 columns passes' '
	put edge.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"int edge(void)" "{" \
		"	return 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1234567890 + 123456;" "}" &&
	commit "a: add edge

Why the change is made." &&
	check &&
	! grep -q "LONG_LINE" "$W/out"
'

test_expect_success 'a line beyond 100 columns is reported' '
	put wide.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"int wide(void)" "{" \
		"	return 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1234567890 + 1;" "}" &&
	commit "a: add wide

Why the change is made." &&
	! check &&
	grep -q "^WARNING:LONG_LINE: line length of 108 exceeds 100 columns" "$W/out"
'

test_expect_success 'a string literal running past 100 columns is not reported' '
	put names.h "/* SPDX-License-Identifier: BSD-2-Clause */" "" \
		"#define NAMES_LONG_PIN_PATH	NAMES_DIR \"/a_pin_name_that_runs_well_past_the_limit_of_the_style_check_link\"" &&
	commit "a: add a long name

Why the change is made." &&
	check &&
	! grep -q "LONG_LINE" "$W/out"
'

test_expect_success 'a commit touching no C source still has its message checked' '
	put run.sh "#!/bin/sh" "$(printf "%0150d" 0)" &&
	commit "a: a shell file

Why the change is made.

Co-Authored-By: Some Agent <noreply@agent.example.org>" &&
	! check &&
	grep -q "BAD_SIGN_OFF" "$W/out" &&
	! grep -q "LONG_LINE" "$W/out"
'

test_expect_success 'a commit touching no C source passes on its message alone' '
	put ok.sh "#!/bin/sh" "echo ok" &&
	commit "a: another shell file

Why the change is made." &&
	check
'

test_expect_success 'vendored and generated sources are left alone' '
	put vendor/libx/x.c "int x; // vendored" &&
	put upatches/kernel-cve/vmlinux.h "struct a { int b; }; // dumped" &&
	put upatches/kernel-obs/watch_generated.h "// generated" &&
	commit "a: vendor

Why the change is made." &&
	check
'

test_expect_success 'a subject beyond 75 characters is an error' '
	put sub.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"int sub(void)" "{" "	return 0;" "}" &&
	commit "a: $(printf "%080d" 0)

Why the change is made." &&
	! check &&
	grep -q "^ERROR:SUBJECT_LENGTH: the subject runs to 83 characters" "$W/out"
'

test_expect_success 'the userspace spellings checkpatch would reject pass' '
	put user.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"#include <string.h>" "" "#include <shirudo/misc.h>" "" \
		"__u32 user(X509 *c, char *dst, const char *src)" "{" \
		"	gzFile gz = NULL;" "" "	(void)gz;" "	strscpy(dst, src, 8);" \
		"	return (__u32)ASN1_INTEGER_get(X509_get_serialNumber(c));" "}" &&
	commit "a: userspace

Why the change is made." &&
	check
'

test_expect_success 'a range reports every failing commit' '
	! check -3 HEAD &&
	grep -q "1 of 3 commits have style problems" "$W/err"
'

test_expect_success '--types lists what stays enabled' '
	check --types &&
	grep -qx "C99_COMMENTS" "$W/out" &&
	grep -qx "BLOCK_COMMENT_STYLE" "$W/out" &&
	grep -qx "KERNEL_INT_TYPES" "$W/out" &&
	grep -qx "NUMBER_PARSING" "$W/out" &&
	grep -qx "STRING_COPY" "$W/out" &&
	grep -qx "STRING_FORMAT" "$W/out" &&
	! grep -qx "CAMELCASE" "$W/out" &&
	! grep -qx "GIT_COMMIT_ID" "$W/out"
'

test_expect_success 'the C library'"'"'s integer names are refused in code only' '
	printf "%s\n" "/* uint32_t in a comment */" \
		"static const char *name = \"uint64_t\";" \
		"static __u16 kept;" "static uint32_t width;" \
		"#pragma GCC poison uint8_t uint32_t" \
		"static unsigned long mask;" "static unsigned char byte;" \
		>>"$R/good.c" &&
	! check --diff &&
	grep -q "^ERROR:KERNEL_INT_TYPES: spell uint32_t as __u32" "$W/out" &&
	grep -q "^ERROR:KERNEL_INT_TYPES: spell unsigned long as __u64" "$W/out" &&
	grep -q "^ERROR:KERNEL_INT_TYPES: spell unsigned char as __u8" "$W/out" &&
	[ "$(grep -c "^ERROR:KERNEL_INT_TYPES" "$W/out")" = 3 ] &&
	git -C "$R" checkout -q -- good.c
'

test_expect_success 'the C library'"'"'s number parsers are refused outside the tests' '
	printf "%s\n" "/* strtoul() in a comment */" \
		"static const char *name = \"atoi(s)\";" "" \
		"long parse(const char *s)" "{" \
		"	return strtoll(s, NULL, 10) + atoi(s);" "}" \
		>>"$R/good.c" &&
	! check --diff &&
	grep -q "^ERROR:NUMBER_PARSING: parse numbers with parse_u64(), parse_s64() or parse_x64() from <shirudo/string.h>, not strtoll()" "$W/out" &&
	[ "$(grep -c "^ERROR:NUMBER_PARSING" "$W/out")" = 1 ] &&
	git -C "$R" checkout -q -- good.c &&
	put testing/helper/args.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"long arg(const char *s)" "{" "	return strtol(s, NULL, 10);" "}" &&
	check --files testing/helper/args.c &&
	rm -r "$R/testing"
'

test_expect_success 'strings are copied with strscpy() outside the tests' '
	printf "%s\n" "/* strcpy() in a comment */" \
		"static const char *op = \"strncpy(a, b, c)\";" "" \
		"void copy(char *d, const char *s)" "{" "	strcpy(d, s);" \
		"	snprintf(d, 8, \"%s\", s);" "	snprintf(d, 8, \"%d\", 1);" "}" \
		>>"$R/good.c" &&
	! check --diff &&
	grep -q "^ERROR:STRING_COPY: copy strings with strscpy() from <shirudo/string.h>, not strcpy()" "$W/out" &&
	grep -q "^ERROR:STRING_COPY: copy strings with strscpy() from <shirudo/string.h>, not snprintf()" "$W/out" &&
	[ "$(grep -c "^ERROR:STRING_COPY" "$W/out")" = 2 ] &&
	git -C "$R" checkout -q -- good.c &&
	put tools/x/name.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"void name(char *d, const char *s)" "{" "	strncpy(d, s, 8);" "}" &&
	! check --files tools/x/name.c &&
	grep -q "^ERROR:STRING_COPY: copy strings with strscpy() from <shirudo/string.h>, not strncpy()" "$W/out" &&
	put testing/helper/name.c "// SPDX-License-Identifier: BSD-2-Clause" "" \
		"void name(char *d, const char *s)" "{" "	strcpy(d, s);" "}" &&
	check --files testing/helper/name.c &&
	rm -r "$R/tools" "$R/testing"
'

test_expect_success 'strings are formatted with strsprintf() outside the tests' '
	printf "%s\n" "/* snprintf() in a comment */" \
		"static const char *op = \"sprintf(a, b)\";" "" \
		"void fmt(char *d, const char *s, va_list ap)" "{" \
		"	snprintf(d, 8, \"%d\", 1);" "	sprintf(d, \"%d\", 1);" \
		"	vsnprintf(d, 8, s, ap);" "	vsprintf(d, s, ap);" \
		"	snprintf(d, 8, \"%s\", s);" \
		"	(void)strsprintf(d, 8, \"%d\", 1);" "}" \
		>>"$R/good.c" &&
	! check --diff &&
	grep -q "^ERROR:STRING_FORMAT: format into a buffer with strsprintf() or vstrsprintf() from <shirudo/string.h>, not snprintf()" "$W/out" &&
	grep -q "^ERROR:STRING_FORMAT: .*, not vsprintf()" "$W/out" &&
	[ "$(grep -c "^ERROR:STRING_FORMAT" "$W/out")" = 4 ] &&
	[ "$(grep -c "^ERROR:STRING_COPY" "$W/out")" = 1 ] &&
	git -C "$R" checkout -q -- good.c &&
	for f in util/string.c util/malloc.c testing/helper/fmt.c; do
		put $f "// SPDX-License-Identifier: BSD-2-Clause" "" \
			"int fmt(char *d)" "{" \
			"	return snprintf(d, 8, \"%d\", 1);" "}" || return 1
	done &&
	check --files util/string.c util/malloc.c testing/helper/fmt.c &&
	rm -r "$R/util" "$R/testing"
'

test_expect_success 'a BPF program keeps the kernel'"'"'s argument types' '
	put hook.bpf.c "// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause" "" \
		"int hook(unsigned long arg, unsigned short port, unsigned char c)" \
		"{" "	return arg > port + c;" "}" &&
	check --files hook.bpf.c &&
	printf "%s\n" "static uint32_t width;" >>"$R/hook.bpf.c" &&
	! check --files hook.bpf.c &&
	grep -q "^ERROR:KERNEL_INT_TYPES: spell uint32_t as __u32" "$W/out" &&
	rm "$R/hook.bpf.c"
'

test_expect_success '--files checks whole files' '
	! check --files bad.c &&
	grep -q "^ERROR:C99_COMMENTS" "$W/out" &&
	check --files good.c good.h &&
	grep -q "style: 2 files checked" "$W/out"
'

test_expect_success 'under GitHub Actions each finding is an annotation' '
	! (cd "$R" && GITHUB_ACTIONS=true sh "$S" --files bad.c) >"$W/out" 2>"$W/err" &&
	grep -q "^::error::ERROR:C99_COMMENTS" "$W/out" &&
	! grep -q "^ERROR:" "$W/out"
'

test_expect_success '--diff checks the uncommitted changes' '
	printf "%s\n" "int extra; // uncommitted" >>"$R/good.c" &&
	! check --diff &&
	grep -q "^ERROR:C99_COMMENTS" "$W/out" &&
	git -C "$R" checkout -q -- good.c &&
	check --diff &&
	grep -q "no uncommitted changes" "$W/out"
'

test_done
