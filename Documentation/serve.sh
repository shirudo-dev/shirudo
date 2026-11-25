#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu

# Make runs recursive recipes even in dry-run, question and touch modes.
# Older versions put long options before the group of short flags.
read -ra makeflags <<< "${MAKEFLAGS-}"
for flag in "${makeflags[@]}"; do
	case $flag in
		--) break ;;
		--*) continue ;;
		*[nqt]*) exit 0 ;;
		*) break ;;
	esac
done

make=$1
out=$2
shift 2

if command -v fswatch >/dev/null 2>&1; then
	watcher=fswatch
elif command -v inotifywait >/dev/null 2>&1; then
	watcher=inotifywait
else
	printf '%s\n' 'hint: install fswatch or inotify-tools to rebuild docs on changes' >&2
	exec "$@"
fi

# Both watchers report absolute paths. Ignore generated files so a
# rebuild cannot trigger another.
docs=$(pwd -P)
out=$(cd "$out" && pwd -P)
out_pattern=$(printf '%s\n' "$out" | sed 's/[][(){}.^$*+?|\\]/\\&/g')
exclude="^${out_pattern}(/|$)"

if [[ $watcher == fswatch ]]; then
	watch=(fswatch -orE -e "$exclude" "$docs")
else
	watch=(inotifywait -qmr -e close_write,create,delete,move --exclude "$exclude"
	       --format '%e' "$docs" "@$out")
fi

# Separate process groups let us stop the watcher and any rebuild it is
# running when the server exits, or stop both jobs on Ctrl-C.
set -m
(
	set +m
	"${watch[@]}" | while IFS= read -r event; do
		"$make" html || printf '%s\n' 'docs serve: docs rebuild failed; watching for the next change' >&2
	done
	printf 'docs serve: %s stopped; docs will no longer rebuild automatically\n' "$watcher" >&2
) &
watch_pid=$!

"$@" &
server_pid=$!

cleanup()
{
	kill -TERM -- "-$watch_pid" 2>/dev/null || :
	kill -INT -- "-$server_pid" 2>/dev/null || :
	wait "$watch_pid" "$server_pid" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'docs serve: watching Documentation/ for changes with %s\n' "$watcher"
wait "$server_pid"
