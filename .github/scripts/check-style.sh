#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-style.sh -- run the kernel's checkpatch.pl, in strict
# mode, over the C sources a commit touches and over its message, the way
# cilium checks its BPF tree, plus the block-comment opener that checkpatch
# leaves to the netdev trees, the kernel's spelling of fixed-width
# integers and the project's number parsers, string copies and formatting.
# The kernel checks that have no meaning in userspace are switched off
# below, each with its reason.
#
#   .github/scripts/check-style.sh [<rev-list arguments>]
#   .github/scripts/check-style.sh --diff
#   .github/scripts/check-style.sh --files [<file>...]
#   .github/scripts/check-style.sh --types
#
# The first form checks commits: the arguments go to git rev-list, a range
# such as origin/main..HEAD or -3 HEAD, and the commit at HEAD alone
# without any. --diff checks the uncommitted changes against HEAD and
# --files whole files, every C source the project writes by default.
# --types lists the checks that stay enabled.
#
# checkpatch.pl is the kernel's and stays out of the tree: CHECKPATCH names
# a copy to use, a kernel tree's scripts/checkpatch.pl for instance, and
# otherwise the pinned release below is fetched into build/checkpatch/ and
# verified before use.

set -eu

KERNEL_TAG=v7.2
CHECKPATCH_PL_SHA256=f8f32e6b559004fcac021e2f6149b6b7ea486924a8bc48297c0f317eddf5e220
SPELLING_SHA256=4095d4a8810f115bae1b7c0d8a1946beb3435f6e22d9a48ac009bb024bad1e68
CONST_STRUCTS_SHA256=ea064f6916a74763468037494aeb270aae34b7c97617e84d424ca5b8733539b2

SUBJECT_MAX=75

die() {
	printf 'check-style: %s\n' "$*" >&2
	exit 2
}

usage() {
	sed -n '/^#   /,/^#$/{s/^#   //;s/^# *//;p;}' "$0" >&2
	exit 2
}

# The checks to ignore: cilium's list first, from its checkpatch image
# (image-tools, images/checkpatch/checkpatch.sh), then what userspace
# adds.
ignored_types() {
	cat <<-EOT
	# Errors
	COMPLEX_MACRO
	GIT_COMMIT_ID
	# Split from GIT_COMMIT_ID after cilium's list was written: a message
	# here cites kernel commits, which are not in this repository.
	UNKNOWN_COMMIT_ID
	MULTISTATEMENT_MACRO_USE_DO_WHILE
	NOT_UNIFIED_DIFF
	# Warnings
	COMMIT_LOG_LONG_LINE
	COMMIT_MESSAGE
	# A string literal is not broken across lines, as the kernel's
	# coding style says of user-visible strings, so that it can be
	# grepped for; the pin and xattr names in util/paths.h run past
	# the limit for that reason.
	LONG_LINE_STRING
	CONSTANT_CONVERSION
	CONST_STRUCT
	EMAIL_SUBJECT
	FILE_PATH_CHANGES
	FROM_SIGN_OFF_MISMATCH
	JIFFIES_COMPARISON
	LINE_CONTINUATIONS
	MACRO_WITH_FLOW_CONTROL
	PRINTK_WITHOUT_KERN_LEVEL
	TRAILING_SEMICOLON
	TRAILING_STATEMENTS
	VOLATILE
	# Checks
	BIT_MACRO
	# Dropping the tolerance makes // comments an error, as cilium does;
	# the SPDX tag of a .c file is rewritten below so it is not one.
	C99_COMMENT_TOLERANCE
	# check-spdx.sh enforces the project's own tag rules, and the
	# rewrite above would fail checkpatch's form check.
	SPDX_LICENSE_TAG
	# The OpenSSL, zlib and tpm2-tss APIs are CamelCase, as is
	# _Static_assert.
	CAMELCASE
	# It asks for the kernel-internal u32, which userspace does not have;
	# check_spellings below asks for __u32 and its kin instead.
	PREFER_KERNEL_TYPES
	# check_spellings below asks for the strscpy() of <shirudo/string.h>
	# in tools/ too, which these leave out, and fallthrough;, __packed
	# and most other compiler.h macros do not exist in userspace, which
	# has those of <shirudo/compiler.h>; BPF has what bpf_helpers.h
	# defines.
	STRCPY
	STRNCPY
	PREFER_FALLTHROUGH
	PREFER_DEFINED_ATTRIBUTE_MACRO
	# BUILD_BUG_ON() is a compile-time assertion; there is no kernel to
	# crash.
	AVOID_BUG
	# The task_prctl LSM hook returns -ENOSYS for "not handled" by
	# contract.
	ENOSYS
	# The usage helpers print the word usage.
	EMBEDDED_FUNCTION_NAME
	# The usage and summary tables are string literals longer than a
	# line.
	SPLIT_STRING
	# A security report arrives by mail and has no URL; Closes: follows
	# a Reported-by: when there is one.
	BAD_REPORTED_BY_LINK
	EOT
}

# The C the project writes: not the vendored libbpf, not the BTF dump the
# kernel-cve package carries and not the headers make -C
# upatches/kernel-obs lists generates. A git command limited to it.
git_c() {
	git "$@" -- '*.c' '*.h' ':(exclude)vendor/' \
		':(exclude)upatches/kernel-cve/vmlinux.h' \
		':(exclude)*_generated.h'
}

verified() {
	[ -f "$1" ] && [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ]
}

# Where the kernel's scripts come from, in the order they are asked. A
# source that fails one script is not asked for the next, so a host that
# does not answer costs its retries once rather than once per script.
fetch_sources='kernel.org github'

source_url() {
	case $1 in
	kernel.org)
		printf '%s\n' "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/scripts/$2?h=$KERNEL_TAG"
		;;
	github)
		printf '%s\n' "https://raw.githubusercontent.com/torvalds/linux/$KERNEL_TAG/scripts/$2"
		;;
	esac
}

# Fetch one of the kernel's scripts at the pinned tag, from kernel.org or
# its GitHub mirror, and keep it only when it hashes as expected. Without
# a connect timeout curl waits out the system's TCP one, over two minutes
# an attempt, on a host that drops what it is sent.
fetch() {
	name=$1
	sum=$2
	dest=$3
	for source in $fetch_sources; do
		if curl -fsSL --connect-timeout 10 --max-time 60 --retry 3 \
			-o "$dest.tmp" "$(source_url "$source" "$name")" &&
		   verified "$dest.tmp" "$sum"; then
			mv "$dest.tmp" "$dest"
			return 0
		fi
		rm -f "$dest.tmp"
		fetch_sources=${fetch_sources#*"$source"}
	done
	die "could not fetch scripts/$name at $KERNEL_TAG with sha256 $sum"
}

locate_checkpatch() {
	if [ -n "${CHECKPATCH:-}" ]; then
		[ -r "$CHECKPATCH" ] || die "CHECKPATCH=$CHECKPATCH: not readable"
		printf '%s\n' "$CHECKPATCH"
		return
	fi
	dir=$PWD/build/checkpatch
	if ! verified "$dir/checkpatch.pl" "$CHECKPATCH_PL_SHA256" ||
	   ! verified "$dir/spelling.txt" "$SPELLING_SHA256" ||
	   ! verified "$dir/const_structs.checkpatch" "$CONST_STRUCTS_SHA256"; then
		command -v curl >/dev/null 2>&1 ||
			die "curl not found; set CHECKPATCH to a kernel tree's scripts/checkpatch.pl"
		mkdir -p "$dir"
		printf 'check-style: fetching the kernel'"'"'s checkpatch.pl at %s into %s\n' \
			"$KERNEL_TAG" "$dir" >&2
		fetch checkpatch.pl "$CHECKPATCH_PL_SHA256" "$dir/checkpatch.pl"
		fetch spelling.txt "$SPELLING_SHA256" "$dir/spelling.txt"
		fetch const_structs.checkpatch "$CONST_STRUCTS_SHA256" \
			"$dir/const_structs.checkpatch"
	fi
	printf '%s\n' "$dir/checkpatch.pl"
}

# Fixed-width integers are spelled the kernel's way, __u32 and its kin from
# <shirudo/types.h> in userspace and from vmlinux.h in BPF, not the C
# library's uint32_t. checkpatch's PREFER_KERNEL_TYPES suggests the
# kernel-internal u32 and leaves tools/ out, so it stays off and this
# reports an added line that names uint8_t through int64_t outside a
# string, a comment or the #pragma GCC poison that refuses them, in the
# form checkpatch reports in, and in userspace one that names unsigned
# char, short, int or long. Those stay where an interface fixes them: BPF
# programs spell hook arguments as the kernel's prototypes do,
# util/elf_target.c passes a type required by libbpf, declared in
# util/libbpf_internal.h; util/sign.c is vendored.
# A call to strtoul() and its kin or atoi() is
# reported too, outside the tests: a number is parsed with parse_u64() and
# its kin from <shirudo/string.h>, which take a length, read nothing past
# it and refuse a sign, blank or base prefix. So is a string copied with
# strcpy() and its kin or with snprintf("%s") on one line: strscpy() always
# terminates and says when it cut. Any other call to sprintf(),
# snprintf() or their va_list forms is reported outside the tests and
# the two files that implement strsprintf() and xasprintf() with them:
# strsprintf() and vstrsprintf() refuse output that does not fit rather
# than cut it.
check_spellings() {
	awk '
	function c_names_kept(f) {
		return f ~ /^(bpf|upatches)\// || f ~ /\.bpf\.c$/ ||
		       f == "util/elf_target.c" ||
		       f == "util/libbpf_internal.h" || f == "util/sign.c"
	}
	function parsers_kept(f) {
		return f ~ /^(bpf|upatches|testing)\// || f ~ /\.bpf\.c$/
	}
	function formatters_kept(f) {
		return parsers_kept(f) || f == "util/string.c" ||
		       f == "util/malloc.c"
	}
	/^\+\+\+ / {
		file = $0
		sub(/^\+\+\+ b\//, "", file)
		incomment = 0
		next
	}
	/^@@ / {
		split($0, h, " ")
		sub(/^\+/, "", h[3])
		split(h[3], r, ",")
		line = r[1] - 1
		incomment = 0
		next
	}
	/^[ +]/ {
		line++
		text = substr($0, 2)
		gsub(/"([^"\\]|\\.)*"/, "\"\"", text)
		code = ""
		while (text != "") {
			if (incomment) {
				if ((end = index(text, "*/")) == 0)
					break
				text = substr(text, end + 2)
				incomment = 0
			} else if ((at = index(text, "/*")) > 0) {
				code = code substr(text, 1, at - 1)
				text = substr(text, at + 2)
				incomment = 1
			} else {
				if ((at = index(text, "//")) > 0)
					text = substr(text, 1, at - 1)
				code = code text
				text = ""
			}
		}
		# A hunk can open inside a comment: " * ..." is one.
		if (code ~ /^[ \t]*\*/)
			next
		if (substr($0, 1, 1) != "+")
			next
		if (code ~ /^[ \t]*#[ \t]*pragma[ \t]+GCC[ \t]+poison[ \t]/)
			next
		if (match(code, /(^|[^A-Za-z0-9_])u?int(8|16|32|64)_t([^A-Za-z0-9_]|$)/)) {
			type = substr(code, RSTART, RLENGTH)
			gsub(/[^A-Za-z0-9_]/, "", type)
			bits = type
			gsub(/[^0-9]/, "", bits)
			printf "ERROR:KERNEL_INT_TYPES: spell %s as %s%s, from <shirudo/misc.h> in userspace\n#%d: FILE: %s:%d:\n%s\n\n",
				type, substr(type, 1, 1) == "u" ? "__u" : "__s", bits,
				NR, file, line, $0
			bad = 1
		} else if (!c_names_kept(file) &&
			   match(code, /(^|[^A-Za-z0-9_])unsigned[ \t]+(char|short|int|long)([^A-Za-z0-9_]|$)/)) {
			type = substr(code, RSTART, RLENGTH)
			if (type ~ /char/) {
				c = "char"
				k = "__u8"
			} else if (type ~ /short/) {
				c = "short"
				k = "__u16"
			} else if (type ~ /int/) {
				c = "int"
				k = "__u32"
			} else {
				c = "long"
				k = "__u64"
			}
			printf "ERROR:KERNEL_INT_TYPES: spell unsigned %s as %s, from <shirudo/misc.h> in userspace\n#%d: FILE: %s:%d:\n%s\n\n",
				c, k, NR, file, line, $0
			bad = 1
		}
		if (!parsers_kept(file) &&
		    match(code, /(^|[^A-Za-z0-9_])(strto(u?ll?|d|f|ld|imax|umax)|ato(i|l|ll|f))[ \t]*\(/)) {
			fn = substr(code, RSTART, RLENGTH)
			gsub(/[^A-Za-z0-9_]/, "", fn)
			printf "ERROR:NUMBER_PARSING: parse numbers with parse_u64(), parse_s64() or parse_x64() from <shirudo/string.h>, not %s()\n#%d: FILE: %s:%d:\n%s\n\n",
				fn, NR, file, line, $0
			bad = 1
		}
		if (!parsers_kept(file) &&
		    (match(code, /(^|[^A-Za-z0-9_])str(n?cpy|n?cat|lcpy)[ \t]*\(/) ||
		     (match(code, /(^|[^A-Za-z0-9_])snprintf[ \t]*\([^,]*,[^,]*,[ \t]*""[ \t]*,/) &&
		      $0 ~ /"%s"[ \t]*,/))) {
			fn = substr(code, RSTART, RLENGTH)
			sub(/\(.*/, "", fn)
			gsub(/[^A-Za-z0-9_]/, "", fn)
			printf "ERROR:STRING_COPY: copy strings with strscpy() from <shirudo/string.h>, not %s()\n#%d: FILE: %s:%d:\n%s\n\n",
				fn, NR, file, line, $0
			bad = 1
		} else if (!formatters_kept(file) &&
			   match(code, /(^|[^A-Za-z0-9_])v?sn?printf[ \t]*\(/)) {
			fn = substr(code, RSTART, RLENGTH)
			gsub(/[^A-Za-z0-9_]/, "", fn)
			printf "ERROR:STRING_FORMAT: format into a buffer with strsprintf() or vstrsprintf() from <shirudo/string.h>, not %s()\n#%d: FILE: %s:%d:\n%s\n\n",
				fn, NR, file, line, $0
			bad = 1
		}
	}
	END { exit bad }
	' "$1"
}

# checkpatch enforces the kernel's block-comment form everywhere but at
# the opener, which only the netdev trees have an opinion on, and theirs
# is the opposite of Documentation/contribute/code/coding-style.rst: a comment
# that runs on past its first line opens with /* alone on that line.
# Report an added line that opens a comment with text and does not close
# it, in the form checkpatch reports in. String literals are blanked
# first.
check_block_comments() {
	awk '
	/^\+\+\+ / { file = $0; sub(/^\+\+\+ b\//, "", file); next }
	/^@@ / {
		split($0, h, " ")
		sub(/^\+/, "", h[3])
		split(h[3], r, ",")
		line = r[1] - 1
		next
	}
	/^[ +]/ { line++ }
	/^\+/ {
		text = substr($0, 2)
		gsub(/"([^"\\]|\\.)*"/, "\"\"", text)
		while ((at = index(text, "/*")) > 0) {
			rest = substr(text, at + 2)
			if ((end = index(rest, "*/")) > 0) {
				text = substr(rest, end + 2)
				continue
			}
			sub(/^\*+/, "", rest)
			sub(/^[ \t]+/, "", rest)
			if (rest != "") {
				printf "ERROR:NETDEV_BLOCK_COMMENT: a block comment opens with /* on a line of its own\n#%d: FILE: %s:%d:\n%s\n\n", NR, file, line, $0
				bad = 1
			}
			break
		}
	}
	END { exit bad }
	' "$1"
}

# Under GitHub Actions each finding also becomes an annotation.
annotate() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		sed 's/^ERROR:/::error::&/; s/^WARNING:/::warning::&/; s/^CHECK:/::warning::&/'
	else
		cat
	fi
}

# Two BPF forms checkpatch does not know. A pointer into an arena carries
# the __arena address space, which checkpatch takes for an identifier and
# the * after it for a multiplication; it becomes __user, an annotation
# checkpatch parses. A BPF program names a kernel symbol or a kconfig value
# with an extern __ksym or __kconfig declaration, which AVOID_EXTERNS
# flags; such a declaration loses its extern, so the check stays on for
# every other extern.
bpf_idioms() {
	perl -ne '
	sub flush {
		$buf =~ s/^(\+\s*)extern\s+/$1/ if $buf =~ /\b__(?:ksym|kconfig)\b/;
		print $buf;
		$in = 0;
	}
	if ($in) {
		if (/^\+/) {
			$buf .= $_;
			flush() if /;\s*$/;
			next;
		}
		flush();
	}
	if (/^\+\s*extern\b/) {
		$buf = $_;
		$in = 1;
		flush() if /;\s*$/;
		next;
	}
	s/\b__arena\b/__user/g if /^[-+ ]/ && !/^(?:\+\+\+|---) /;
	print;
	END { flush() if $in }
	'
}

# Check one patch stream. The // SPDX tag of a .c file becomes the /* */
# form first, so the C99 check, which cannot tell the two uses of //
# apart, sees only real comments, and the BPF forms above are rewritten.
# checkpatch seeds a CamelCase cache from the include/ under its root and
# writes it where it runs, strict mode or not: it runs in the work
# directory, over an empty include/.
check_patch() {
	sed -E 's|^([-+ ])// (SPDX-License-Identifier: .*)$|\1/* \2 */|' "$1" |
		bpf_idioms >"$work/patch"
	shift
	rc=0
	(cd "$work" && perl "$checkpatch" --no-tree --root="$work" --strict \
		--quiet --show-types --ignore "$IGNORE" \
		"$@" "$work/patch") >"$work/out" 2>&1 || rc=1
	check_block_comments "$work/patch" >>"$work/out" || rc=1
	check_spellings "$work/patch" >>"$work/out" || rc=1
	annotate <"$work/out"
	return $rc
}

# A commit that touches no C source still has a message to check, and
# checkpatch reads a message only ahead of a diff: give it one.
fake_diff() {
	printf '%s\n' 'diff --git a/dev/null b/dev/null' \
		'index 000000000000..000000000001 100644' \
		'--- a/dev/null' '+++ b/dev/null' '@@ -1,1 +1,1 @@' '-' '+.'
}

check_subject() {
	subject=$(git log -1 --format=%s "$1")
	if [ "${#subject}" -gt "$SUBJECT_MAX" ]; then
		printf 'ERROR:SUBJECT_LENGTH: the subject runs to %d characters, the limit is %d\n\n' \
			"${#subject}" "$SUBJECT_MAX" | annotate
		return 1
	fi
}

check_commits() {
	if [ $# -eq 0 ]; then
		set -- -1 HEAD
	fi
	commits=$(git rev-list --reverse --no-merges "$@")
	n=$(printf '%s\n' "$commits" | grep -c . || :)
	i=0
	bad=0
	for c in $commits; do
		i=$((i + 1))
		printf '[%d/%d] %s\n' "$i" "$n" "$(git log -1 --format='%h ("%s")' "$c")"
		git_c show --format=email "$c" >"$work/raw"
		if ! grep -q '^diff --git ' "$work/raw"; then
			{ git log -1 --format=email "$c"; fake_diff; } >"$work/raw"
		fi
		failed=0
		check_patch "$work/raw" || failed=1
		check_subject "$c" || failed=1
		bad=$((bad + failed))
	done
	if [ "$bad" -gt 0 ]; then
		printf '%d of %d commits have style problems\n' "$bad" "$n" >&2
		exit 1
	fi
	printf 'style: %d commits checked\n' "$n"
}

check_diff() {
	git_c diff HEAD >"$work/raw"
	if ! grep -q '^diff --git ' "$work/raw"; then
		printf 'style: no uncommitted changes to C sources\n'
		return
	fi
	check_patch "$work/raw" --no-signoff || exit 1
	printf 'style: the uncommitted changes are clean\n'
}

# Whole files, each as a patch that adds it. git diff exits 1 when the
# file has content, which is the point.
# Every type checkpatch knows, less the ignored ones.
list_types() {
	perl "$checkpatch" --list-types | awk 'NR > 2 && NF >= 2 { print $2 }' |
		LC_ALL=C sort >"$work/all"
	ignored_types | grep -v '^#' | LC_ALL=C sort >"$work/ignored"
	{
		LC_ALL=C comm -23 "$work/all" "$work/ignored"
		printf '%s\n' KERNEL_INT_TYPES NETDEV_BLOCK_COMMENT NUMBER_PARSING \
			STRING_COPY STRING_FORMAT
	} | LC_ALL=C sort
}

check_files() {
	if [ $# -eq 0 ]; then
		set -- $(git_c ls-files)
	fi
	: >"$work/raw"
	for f in "$@"; do
		[ -f "$f" ] || die "$f: no such file"
		git diff --no-index -- /dev/null "$f" >>"$work/raw" || :
	done
	check_patch "$work/raw" --no-signoff || exit 1
	printf 'style: %d files checked\n' "$#"
}

# checkpatch runs away from the checkout, so its path must not be
# relative to where the caller stood.
if [ -n "${CHECKPATCH:-}" ]; then
	case $CHECKPATCH in
	/*)
		;;
	*)
		CHECKPATCH=$PWD/$CHECKPATCH
		;;
	esac
fi

cd "$(git rev-parse --show-toplevel)"

mode=commits
case "${1:-}" in
--files)
	mode=files
	shift
	;;
--diff)
	mode='diff'
	shift
	;;
--types)
	mode=types
	shift
	;;
-h|--help)
	usage
	;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/include"

checkpatch=$(locate_checkpatch)
IGNORE=$(ignored_types | grep -v '^#' | paste -sd, -)

case "$mode" in
commits)
	check_commits "$@"
	;;
diff)
	check_diff
	;;
files)
	check_files "$@"
	;;
types)
	list_types
	;;
esac
