# A script from the start

A whole CI check in the tree's layout, which passes `shellcheck` and
runs under dash: the header, `set -eu`, the traps around one scratch
directory, a usage error with status 2, every finding reported with an
annotation under `GITHUB_ACTIONS`, status 1 with a count, and one line
on stdout when it passes. Start a script from it and cut what the
script does not need; a test starts from the `functional-tests` skill
instead.

```sh
#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-example.sh -- what the script checks or does, and
# the why a reader cannot get from the code.
#
#   .github/scripts/check-example.sh <file>...

set -eu

bad=0
work=

report() {
	bad=$((bad + 1))
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error file=%s::%s\n' "$1" "$2"
	fi
	printf '%s: %s\n' "$1" "$2" >&2
}

cleanup() {
	[ -z "$work" ] || rm -rf "$work"
}

[ $# -gt 0 ] || { printf 'usage: %s <file>...\n' "$0" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || {
	printf 'check-example: jq not found; install jq\n' >&2
	exit 2
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
work=$(mktemp -d)

for f; do
	jq -e . "$f" >"$work/out" 2>&1 || report "$f" 'not JSON'
done

if [ "$bad" -gt 0 ]; then
	printf '%d of %d files fail the check\n' "$bad" "$#" >&2
	exit 1
fi
printf 'example: %d files checked\n' "$#"
```

A script with several failures of its own, rather than findings, puts
them through one `die()`:

```sh
die() {
	printf 'check-example: %s\n' "$*" >&2
	exit 1
}
```
