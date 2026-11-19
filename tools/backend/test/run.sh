#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# test/run.sh -- run the SQL tests against a ClickHouse container of its
# own, at the image testing/vm/stack-lib.sh pins.
#
#   test/run.sh [<name>...]
#
# Each test is test/<name>.sql with the output it must print in
# test/<name>.expected. Every test starts from an empty schema, loaded
# from sql/, as an installation loads it: the files in order, then
# sql/apply-retention.sh. A test of what that script applies puts the
# settings it wants in test/<name>.setup.sql, which runs between the two;
# a test whose script needs rows to read puts them there too.
# A test that has a test/<name>.sh runs it next, with CLICKHOUSE_CLIENT
# naming the client of the test's server, as the jobs under jobs/ read
# it; what the script prints comes before the output of the SQL in
# test/<name>.expected, and a script that fails fails the test. A
# script that exits with status 77 skips the test, and the first line it
# printed says why.
# Without names, all tests run. A test named <name>-stub
# depends on the answers of test/stub-quote-check.sh and is skipped when
# SHIRUDO_QUOTE_CHECK names another checker.
#
#   SHIRUDO_QUOTE_CHECK  the shirudo-quote-check program to install as
#                        tpm_quote_check; it has to run inside the
#                        container. Default: test/stub-quote-check.sh.
#   CONTAINER_RUNTIME    docker or podman. Default: the first one found.
#   CLICKHOUSE_IMAGE     another image than the pinned one.

set -eu

CLICKHOUSE_IMAGE=${CLICKHOUSE_IMAGE:-docker.io/clickhouse/clickhouse-server@sha256:d426d2f612e1e189c90f9a3f8dcd85a03c6851273833817a296bb327e63aa7a7}

repo=$(cd "$(dirname "$0")/.." && pwd)
checker=${SHIRUDO_QUOTE_CHECK:-$repo/test/stub-quote-check.sh}
container=shirudo-backend-test-$$
work=

die()
{
	printf 'run.sh: %s\n' "$1" >&2
	exit 2
}

cleanup()
{
	"$runtime" rm -fv "$container" >/dev/null 2>&1 || :
	[ -z "$work" ] || rm -rf "$work"
}

client()
{
	"$runtime" exec -i "$container" clickhouse-client "$@"
}

wait_for()
{
	attempt=0
	until client --query "$1" 2>/dev/null | grep -q .; do
		attempt=$((attempt + 1))
		if [ "$attempt" -ge 150 ]; then
			"$runtime" logs "$container" >&2 || :
			die "$2"
		fi
		sleep 0.2
	done
}

load_schema()
{
	client --query 'DROP DATABASE IF EXISTS shirudo SYNC' &&
	client --query 'DROP DATABASE IF EXISTS otel SYNC' || return 1
	for file in "$repo"/sql/*.sql; do
		client <"$file" || return 1
	done
	if [ -f "$repo/test/$1.setup.sql" ]; then
		client <"$repo/test/$1.setup.sql" || return 1
	fi
	"$repo/sql/apply-retention.sh" \
		"$runtime" exec -i "$container" clickhouse-client
}

run_step()
{
	[ -f "$repo/test/$1.sh" ] || return 0
	CLICKHOUSE_CLIENT="$runtime exec -i $container clickhouse-client" \
		sh "$repo/test/$1.sh" >"$work/out" 2>>"$work/log"
}

run_test()
{
	: >"$work/out"
	step=0
	if load_schema "$1" >"$work/log" 2>&1; then
		run_step "$1" || step=$?
	else
		step=1
	fi
	if [ "$step" -eq 77 ]; then
		printf 'skip %s (%s)\n' "$1" "$(head -n 1 "$work/out")"
		return 0
	fi
	if [ "$step" -eq 0 ] &&
	   client <"$repo/test/$1.sql" >>"$work/out" 2>>"$work/log" &&
	   diff -u "$repo/test/$1.expected" "$work/out" >>"$work/log"; then
		printf 'ok %s\n' "$1"
		return 0
	fi
	printf 'not ok %s\n' "$1"
	sed 's/^/    /' "$work/log"
	return 1
}

if [ -n "${CONTAINER_RUNTIME:-}" ]; then
	runtime=$CONTAINER_RUNTIME
elif command -v docker >/dev/null 2>&1; then
	runtime=docker
elif command -v podman >/dev/null 2>&1; then
	runtime=podman
else
	die 'needs docker or podman'
fi
[ -f "$checker" ] || die "no quote checker at $checker"

if [ $# -eq 0 ]; then
	for file in "$repo"/test/*.sql; do
		name=${file##*/}
		case "$name" in
		*.setup.sql) continue ;;
		esac
		set -- "$@" "${name%.sql}"
	done
fi
for name in "$@"; do
	[ -f "$repo/test/$name.sql" ] || die "no test/$name.sql"
	[ -f "$repo/test/$name.expected" ] || die "no test/$name.expected"
done

trap cleanup EXIT
trap 'exit 2' HUP INT TERM
work=$(mktemp -d)

"$runtime" run -d --name "$container" -e CLICKHOUSE_SKIP_USER_SETUP=1 \
	"$CLICKHOUSE_IMAGE" >/dev/null || die "cannot start $CLICKHOUSE_IMAGE"
wait_for 'SELECT 1' 'ClickHouse did not start'

# The server picks the function up from its configuration directory and
# the program from user_scripts, where an installation puts them too.
cp "$checker" "$work/shirudo-quote-check"
chmod 0755 "$work/shirudo-quote-check"
"$runtime" exec "$container" mkdir -p /var/lib/clickhouse/user_scripts
"$runtime" cp "$work/shirudo-quote-check" \
	"$container:/var/lib/clickhouse/user_scripts/shirudo-quote-check"
"$runtime" cp "$repo/clickhouse/tpm_quote_check_function.xml" \
	"$container:/etc/clickhouse-server/tpm_quote_check_function.xml"
client --query 'SYSTEM RELOAD FUNCTIONS'
wait_for "SELECT 1 FROM system.functions WHERE name = 'tpm_quote_check'" \
	'tpm_quote_check was not loaded'

failed=0
for name in "$@"; do
	case "$name" in
	*-stub)
		if [ -n "${SHIRUDO_QUOTE_CHECK:-}" ]; then
			printf 'skip %s (needs the stub checker)\n' "$name"
			continue
		fi ;;
	esac
	run_test "$name" || failed=$((failed + 1))
done

if [ "$failed" -ne 0 ]; then
	printf '%d of %d tests failed\n' "$failed" "$#"
	exit 1
fi
printf 'no test failed\n'
