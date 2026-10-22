#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1120 -- delete the upatch t1118 applied through an appended tree
# operation, then add it back in the generation after that.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
CACHE=/var/lib/shirudo/bpm/upatch-tree/artifacts
WORK=$(mktemp -d)

for fixture in \
	"$TREE_REPO/manifests/deleted" \
	"$TREE_REPO/manifests/restored" \
	"$FIXTURES/shirudo-test-tree-match.upatch" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 3 ] &&
	[ -e "$MATCH_PIN" ] ||
	test_skip_all "tree state is not where t1119 leaves it"

cleanup()
{
	tree_registry_stop
	if [ -e "$MATCH_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

tree_configure deleted
tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'a delete operation detaches through the fetched unload directive' '
	tree_sync "$WORK/first.json" &&
	[ "$(report_field selected <"$WORK/first.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/first.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/first.json")" = 4 ] &&
	[ ! -e "$MATCH_PIN" ] &&
	! grep -q "/v2/shirudo/tree-match/" "$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-match-unload/manifests/sha256:" \
		"$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-match-unload/blobs/sha256:" \
		"$WORK/requests.log"
'

test_expect_success 'adding it back loads the cached artifact without a fetch' '
	tree_configure restored &&
	: >"$WORK/requests.log" &&
	tree_sync "$WORK/second.json" &&
	[ "$(report_field selected <"$WORK/second.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/second.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/second.json")" = 5 ] &&
	[ -e "$MATCH_PIN" ] &&
	[ "$(find "$CACHE" -name "*.upatch" -type f | wc -l)" = 3 ] &&
	! grep -q "/v2/shirudo/tree-" "$WORK/requests.log"
'

test_done
