#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/labels-put: a file of sets by node_id, by ak_name and by
# config_root loads whole, from a file and from standard input; a second
# put replaces the sets it names, clears one with an empty set, and keeps
# those it does not name; each put names the keys whose sets disagree;
# --check loads nothing. Then what it refuses, each with a message and
# nothing loaded: a file that is not JSON or not of the form, a set that
# names its node twice or not at all, two sets for one name, a key or
# value node.labels could not hold, too many labels, a missing file and
# wrong usage.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/labels-put

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

# refused <what> <file content>: the job on that file.
refused()
{
	printf '%s\n' "$2" >"$work/bad.json"
	run "$1" "$job" "$work/bad.json"
}

cat >"$work/first.json" <<'SETS'
{"nodes": [
 {"node_id": "edge-01", "labels": {"role": "edge", "site": "fra"}},
 {"node_id": "edge-02", "labels": {"role": "edge", "site": "ams"}},
 {"ak_name": "000b03", "labels": {"role": "core"}},
 {"config_root": "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1", "labels": {"image": "base", "role": "lab"}}
]}
SETS
run 'first put' "$job" "$work/first.json"

cat >"$work/second.json" <<'SETS'
{"nodes": [
 {"node_id": "edge-02", "labels": {}},
 {"ak_name": "000b01", "labels": {"role": "edge", "site": "fra", "rack": "r 7"}}
]}
SETS
run 'second put' "$job" - <"$work/second.json"
run 'check' "$job" --check "$work/first.json"

long=$(printf '%0256d' 0)
many=$(i=0; while [ $i -lt 65 ]; do printf '"k%d": "v",' $i; i=$((i + 1)); done)
refused 'not json' '{"nodes": ['
refused 'not the form' '[]'
refused 'another top key' '{"nodes": [], "extra": 1}'
refused 'both names' '{"nodes": [{"node_id": "a", "ak_name": "0b", "labels": {}}]}'
refused 'no name' '{"nodes": [{"labels": {}}]}'
refused 'short root' '{"nodes": [{"config_root": "c1c1", "labels": {}}]}'
refused 'ak not hex' '{"nodes": [{"ak_name": "000B", "labels": {}}]}'
refused 'unknown key' '{"nodes": [{"node_id": "a", "labels": {}, "label": {}}]}'
refused 'two sets' '{"nodes": [{"node_id": "a", "labels": {}}, {"node_id": "a", "labels": {"x": "y"}}]}'
refused 'key twice' '{"nodes": [{"node_id": "a", "labels": {"x": "1", "x": "2"}}]}'
refused 'equals in key' '{"nodes": [{"node_id": "a", "labels": {"a=b": "c"}}]}'
refused 'hash first' '{"nodes": [{"node_id": "a", "labels": {"#a": "c"}}]}'
refused 'blank at end' '{"nodes": [{"node_id": "a", "labels": {"a": "c "}}]}'
refused 'value not text' '{"nodes": [{"node_id": "a", "labels": {"a": 1}}]}'
refused 'long value' "{\"nodes\": [{\"node_id\": \"a\", \"labels\": {\"a\": \"$long\"}}]}"
refused 'too many' "{\"nodes\": [{\"node_id\": \"a\", \"labels\": {${many%,}}}]}"
(cd "$work" && run 'no file' "$job" none.json)
run 'no argument' "$job"
