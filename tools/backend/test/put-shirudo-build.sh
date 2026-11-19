#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# tools/put-shirudo-build: allows builds given by version_id and by a
# binary that prints its own, once each; a build already allowed is left
# as it is. Then what it refuses, each with a message and nothing loaded:
# an argument that is neither, a binary that gives no version_id, a note
# with a control character and wrong usage.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
helper=$test/../../put-shirudo-build

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

a=$(printf '%064d' 0 | tr 0 a)
b=$(printf '%064d' 0 | tr 0 b)
c=$(printf '%064d' 0 | tr 0 c)

# run <what> <command>...: run a command, then name its status.
run()
{
	what=$1
	shift
	status=0
	"$@" 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
}

# A shirudo that knows only version --version-id.
printf '#!/bin/sh\n[ "$*" = "version --version-id" ] && echo %s\n' "$b" >"$work/shirudo"
printf '#!/bin/sh\necho not-a-build\n' >"$work/broken"
chmod +x "$work/shirudo" "$work/broken"

run 'first put' "$helper" --note 'test-vm build' "$a" "$work/shirudo" "$a"
run 'again' "$helper" "$a" "$c"
run 'neither' "$helper" "$(printf '%063d' 0)"
run 'upper' "$helper" "$(printf '%064d' 0 | tr 0 A)"
(cd "$work" && run 'no build from it' "$helper" ./broken)
run 'note with a tab' "$helper" --note "$(printf 'a\tb')" "$c"
run 'no build' "$helper" --note x
run 'no argument' "$helper"
