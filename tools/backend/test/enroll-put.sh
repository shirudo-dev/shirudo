#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/enroll-put: a builder's file enrolls a key the backend has seen,
# naming its node, and one it has not; the same file again changes
# nothing; a file that binds an enrolled key otherwise is refused whole;
# --check loads nothing; a rename after the enrollment wins over the
# builder's name. Then what it refuses, each with a message and nothing
# loaded: a file that is not JSON or not of the form, a name that is not
# a TPM name, a key bound twice, a node_id with a control character, a
# missing file and wrong usage.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/enroll-put

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

a=000b$(printf '%064d' 0 | tr 0 a)
b=000b$(printf '%064d' 0 | tr 0 b)
c=000b$(printf '%064d' 0 | tr 0 c)
e=000b$(printf '%064d' 0 | tr 0 e)

# run <what> <command>...: run a command, then name its status.
run()
{
	what=$1
	shift
	status=0
	"$@" 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
}

# refused <what> <file content>: the job on that file.
refused()
{
	printf '%s\n' "$2" >"$work/bad.json"
	run "$1" "$job" "$work/bad.json"
}

cat >"$work/first.json" <<BINDINGS
{"source": "vm-host-1", "nodes": [
 {"ak_name": "$a", "ek_name": "$e", "node_id": "edge-01"},
 {"ak_name": "$b"}
]}
BINDINGS
run 'first put' "$job" "$work/first.json"
run 'again' "$job" - <"$work/first.json"

cat >"$work/other.json" <<BINDINGS
{"source": "vm-host-2", "nodes": [
 {"ak_name": "$c", "node_id": "edge-03"},
 {"ak_name": "$a", "ek_name": "$e", "node_id": "edge-09"}
]}
BINDINGS
run 'rebound' "$job" "$work/other.json"
printf '{"source": "vm-host-2", "nodes": [{"ak_name": "%s"}]}\n' "$c" >"$work/check.json"
run 'check' "$job" --check "$work/check.json"

# shellcheck disable=SC2086 # a command with its options, to be split
$CLICKHOUSE_CLIENT --query "INSERT INTO shirudo.nodes (ak_name, node_id)
	SELECT '$b', argMinState('core-01', toDateTime64(0, 3))"

refused 'not json' '{"nodes": ['
refused 'no source' '{"nodes": []}'
refused 'source empty' '{"source": "", "nodes": []}'
refused 'no ak' '{"source": "s", "nodes": [{"node_id": "x"}]}'
refused 'short ak' '{"source": "s", "nodes": [{"ak_name": "000b01"}]}'
refused 'upper ak' "{\"source\": \"s\", \"nodes\": [{\"ak_name\": \"000B${a#000b}\"}]}"
refused 'bad ek' "{\"source\": \"s\", \"nodes\": [{\"ak_name\": \"$c\", \"ek_name\": \"\"}]}"
refused 'unknown key' "{\"source\": \"s\", \"nodes\": [{\"ak_name\": \"$c\", \"trust\": \"enrolled\"}]}"
refused 'bound twice' "{\"source\": \"s\", \"nodes\": [{\"ak_name\": \"$c\"}, {\"ak_name\": \"$c\"}]}"
refused 'control in node_id' "{\"source\": \"s\", \"nodes\": [{\"ak_name\": \"$c\", \"node_id\": \"a\\u0007\"}]}"
(cd "$work" && run 'no file' "$job" none.json)
run 'no argument' "$job"
