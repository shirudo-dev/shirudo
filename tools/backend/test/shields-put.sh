#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/shields-put over the rows of xtop-nodes.setup.sql: a catalog of
# three shields loads whole, xfs-fix, which the tree fleet-base carries,
# ssl-fix and probe, which fixes nothing; a second put from standard
# input adds ssl-fix at 1.1.0 beside its 1.0.0; --check loads nothing.
# Then what it refuses, each with a message and nothing loaded: a file
# that is not JSON or not of the form, a shield with a key too many or
# too few, a name, version, digest or advisory bpm build or bpm push
# would refuse, a reference of another package or version, a selector
# that is not an object, a description with a control character, one
# shield twice, a missing file and wrong usage. Last, the query the
# shields view of tools/xtop sends for the available shields, with the
# names and types of its columns, which the view reads by name, and
# without the time of the put, which changes from run to run.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/shields-put
query=$test/../../xtop/sql/shields-available.sql

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# run <what> <command>...: run a command, then name its status.
run()
{
	what=$1
	shift
	status=0
	"$@" 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
}

reg=oci://registry.example.com/shields
d1=sha256:$(printf '%064d' 1)
d2=sha256:$(printf '%064d' 2)
d3=sha256:$(printf '%064d' 3)
d4=sha256:$(printf '%064d' 4)

# shield <id> <package> <version> <digest> <fixes> [<selector>]
shield()
{
	printf '{"id": "%s", "package": "%s", "version": "%s", "reference": "%s/%s:%s", "manifest_digest": "%s", "fixes": %s, "selector": %s, "description": "%s at %s"}' \
		"$1" "$2" "$3" "$reg" "$2" "$3" "$4" "$5" "${6:-{\}}" "$1" "$3"
}

# refused <what> <file content>: the job on that file.
refused()
{
	printf '%s\n' "$2" >"$work/bad.json"
	run "$1" "$job" "$work/bad.json"
}

printf '{"shields": [%s, %s, %s]}\n' \
	"$(shield xfs-fix xfs-fix 1.0.0 "$d1" '["EXAMPLE-0101"]' '{"labels": {"role": ["edge"]}}')" \
	"$(shield ssl-fix ssl-fix 1.0.0 "$d2" '["EXAMPLE-0202"]')" \
	"$(shield probe probe 0.1.0 "$d3" '[]')" >"$work/first.json"
run 'first put' "$job" "$work/first.json"
printf '{"shields": [%s]}\n' \
	"$(shield ssl-fix ssl-fix 1.1.0 "$d4" '["EXAMPLE-0202", "EXAMPLE-0303"]')" >"$work/second.json"
run 'second put' "$job" - <"$work/second.json"
run 'check' "$job" --check "$work/first.json"

ok=$(shield a a 1.0.0 "$d1" '[]')
refused 'not json' '{"shields": ['
refused 'not the form' '{"nodes": []}'
refused 'key too many' "{\"shields\": [${ok%\}}, \"extra\": 1}]}"
refused 'key too few' '{"shields": [{"id": "a"}]}'
refused 'dot first' "{\"shields\": [$(shield .a a 1.0.0 "$d1" '[]')]}"
refused 'bad package' "{\"shields\": [$(shield a -a 1.0.0 "$d1" '[]')]}"
refused 'bad version' "{\"shields\": [$(shield a a '1.0 0' "$d1" '[]')]}"
refused 'bad digest' "{\"shields\": [$(shield a a 1.0.0 sha256:ABC '[]')]}"
refused 'bad advisory' "{\"shields\": [$(shield a a 1.0.0 "$d1" '["A B"]')]}"
refused 'advisory twice' "{\"shields\": [$(shield a a 1.0.0 "$d1" '["A", "A"]')]}"
refused 'other package' "{\"shields\": [$(printf '%s' "$ok" | sed 's|shields/a:|shields/b:|')]}"
refused 'other version' "{\"shields\": [$(printf '%s' "$ok" | sed 's|a:1.0.0|a:2.0.0|')]}"
refused 'selector not object' "{\"shields\": [$(shield a a 1.0.0 "$d1" '[]' '[]')]}"
refused 'control in description' "{\"shields\": [$(printf '%s' "$ok" | sed 's|a at 1.0.0|a\\u0007|')]}"
refused 'twice' "{\"shields\": [$ok, $ok]}"
(cd "$work" && run 'no file' "$job" none.json)
run 'no argument' "$job"

{
	printf '%s\n' "SELECT * EXCEPT (put_ms) FROM ("
	sed '/^--/d' "$query"
	printf '%s\n' ") ORDER BY id FORMAT TSVWithNamesAndTypes"
} | $CLICKHOUSE_CLIENT
