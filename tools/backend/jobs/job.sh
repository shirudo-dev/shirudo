#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/job.sh -- what the jobs share, read by each with its name in
# prog: its messages, its scratch directory and the commands it runs.

work=

die()
{
	printf '%s: %s\n' "$prog" "$1" >&2
	exit 1
}

cleanup()
{
	[ -z "$work" ] || rm -rf "$work"
}

# make_work: a scratch directory in work that leaves with the job.
make_work()
{
	trap cleanup EXIT
	trap 'exit 1' HUP INT TERM
	work=$(mktemp -d)
}

client()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	${CLICKHOUSE_CLIENT:-clickhouse-client} "$@"
}

s3()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	${S3_CLIENT:-aws} "$@"
}

# insert <table> <rows.jsonl>: load the rows, none when the file is empty.
insert()
{
	[ -s "$2" ] || return 0
	client --query "INSERT INTO shirudo.$1 FORMAT JSONEachRow" <"$2" ||
		die "cannot insert into shirudo.$1"
}
