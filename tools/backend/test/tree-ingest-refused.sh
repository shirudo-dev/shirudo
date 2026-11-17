#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# jobs/tree-ingest refuses input that is not what `bpm tree show
# --walk` prints, a walk whose segments do not join up, a failed `bpm
# tree show` and another manifest for a generation it has loaded, each
# with a message and without inserting anything. The first form of the
# job, which runs the command, is shown with test/stub-shirudo.sh.

set -eu

test=$(cd "$(dirname "$0")" && pwd)
job=$test/../jobs/tree-ingest
show=$test/tree-show-1.1.0.json
walk=$test/tree-show-walk.json

query()
{
	# shellcheck disable=SC2086 # a command with its options, to be split
	$CLICKHOUSE_CLIENT --query "$1"
}

rows()
{
	query "SELECT (SELECT count() FROM shirudo.tree_pubs),
		      (SELECT count() FROM shirudo.tree_ops),
		      (SELECT count() FROM shirudo.upatch_fixes)"
}

# refused <what> [<sed expression>...]: the stored output, edited, must
# be refused with status 1.
refused()
{
	what=$1
	shift
	[ $# -gt 0 ] || set -- -e ''
	status=0
	sed "$@" "$input" | "$job" --input - 2>&1 || status=$?
	printf '%s: status %d\n' "$what" "$status"
	[ "$status" -eq 1 ]
}

input=$show

refused 'empty' -e d
refused 'not JSON' -e 's/^{/[/'
refused 'cut short' -e 's/"head".*//'
refused 'an array' -e 's/^/[/' -e 's/$/]/'
refused 'two objects' -e p
refused 'a line per value' -e 's/^.*"document"://' -e 's/}$//'
refused 'no manifest digest' -e 's/"manifest_digest":"sha256:4c1d[0-9a-f]*",//'
refused 'no document' -e 's/"document"/"documents"/'
refused 'digest without algorithm' -e 's/"manifest_digest":"sha256:4c1d/"manifest_digest":"4c1d/'
refused 'short digest' -e 's/"layer_digest":"sha256:9ecc/"layer_digest":"sha256:9ec/'
refused 'schema 2' -e 's/"schema":1/"schema":2/'
refused 'tree_id' -e 's/"tree_id":"fleet-base"/"tree_id":"fleet base"/'
refused 'generation' -e 's/"generation":3/"generation":"3"/'
refused 'negative seq' -e 's/"seq":2/"seq":-2/'
refused 'fractional seq' -e 's/"head":{"seq":3}/"head":{"seq":3.0}/'
refused 'seq twice' -e 's/{"seq":2/{"seq":1/'
refused 'op' -e 's/"op":"delete"/"op":"replace"/'
refused 'selector' -e 's/"selector":{"labels":{"role":\["edge"\]}}/"selector":"edge"/'
refused 'no artifact' -e 's/"artifact":/"artefact":/'
refused 'operations' -e 's/"operations":\[/"operations":{"list":[/' -e 's/\],"head"/]},"head"/'
refused 'key twice' -e 's/"generation":3/"generation":3,"generation":4/'
refused 'segment' -e 's/"base":{"seq":0}/"base":{"seq":2}/'
refused 'base keys at seq 0' \
	-e 's/"base":{"seq":0}/"base":{"seq":0,"history_root":"'"$(printf '%064d' 0)"'"}/'
refused 'operation past head' -e 's/"head":{"seq":3}/"head":{"seq":2}/'

input=$walk
seg2='"seq":2,"segment_manifest_digest":"sha256:2960661252c50e7232cd9781a0ccdbee045bfc40e2f081d89ba3c8fbe1c23495"'
refused 'walk from a later segment' -e 1d
refused 'segments newest first' -e '1!G;h;$!d'
refused 'a segment left out' -e 2d
refused 'base not the head before' -e "s/$seg2/\"seq\":1,\"segment_manifest_digest\":\"sha256:2960661252c50e7232cd9781a0ccdbee045bfc40e2f081d89ba3c8fbe1c23495\"/"
refused 'another predecessor' -e "2s/\"segment_manifest_digest\":\"sha256:2960/\"segment_manifest_digest\":\"sha256:3960/"
refused 'no predecessor' -e "2s/,\"segment_manifest_digest\":\"sha256:[0-9a-f]*\"//"
refused 'no history root' -e '2s/,"history_root":"[0-9a-f]*"//'
refused 'history root with sha256:' -e '2s/"history_root":"/"history_root":"sha256:/'
refused 'generation going back' -e '3s/"generation":5/"generation":4/'
refused 'another tree' -e '3s/"tree_id":"fleet-segments"/"tree_id":"fleet-base"/'
refused 'operation below base' -e '3s/{"seq":5,/{"seq":4,/'
refused 'no operations' -e '3s/"operations":\[.*\],"head"/"operations":[],"head"/'
refused 'key twice in a segment' -e '2s/"generation":4/"generation":4,"generation":4/'
input=$show
echo 'rows after the refusals:'
rows

status=0
STUB_SHOW_OUTPUT=$show STUB_SHOW_STATUS=1 "$job" \
	--shirudo "$test/stub-shirudo.sh" --cert /certs/operator.pem \
	oci://registry.example.com/shirudo/fleet-base 2>&1 || status=$?
printf 'failed command: status %d\n' "$status"
[ "$status" -eq 1 ]
rows

status=0
"$job" oci://registry.example.com/shirudo/fleet-base 2>&1 || status=$?
printf 'no certificate: status %d\n' "$status"
"$job" 2>&1 || status=$?
printf 'no repository: status %d\n' "$status"

STUB_SHOW_OUTPUT=$show SHIRUDO=$test/stub-shirudo.sh \
	TREE_REPOSITORY=oci://registry.example.com/shirudo/fleet-base \
	TREE_REFERENCE=tree TREE_CERT=/certs/operator.pem "$job" 2>&1

refused 'another manifest' -e 's/"manifest_digest":"sha256:4c1d/"manifest_digest":"sha256:5c1d/'

# One segment of a walk under another manifest than the loaded one
# refuses the whole walk, also the segments that are new.
head -n 2 "$walk" | "$job" --input - 2>&1
input=$walk
refused 'another manifest in a walk' -e 's/sha256:e114/sha256:f114/g'
