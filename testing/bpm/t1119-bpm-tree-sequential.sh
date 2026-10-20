#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1119 -- re-sync the publication t1118 applied, then follow the tree to
# the next generation and apply only the operation it appends.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
SKIP_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-skip/link
CACHE=/var/lib/shirudo/bpm/upatch-tree/artifacts
WORK=$(mktemp -d)

for fixture in \
	"$TREE_REPO/manifests/stable" \
	"$TREE_REPO/manifests/updated" \
	"$FIXTURES/shirudo-test-tree-skip.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "${SHIRUDO_TEST_MODE:-legacy}" = verity ] || [ ! -e "$TREE_CONFIG" ] || test_skip_all "tree config already exists"
[ "${SHIRUDO_TEST_MODE:-legacy}" = verity ] || [ ! -e "$TREE_LABELS" ] || test_skip_all "node labels already exist"
[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 2 ] ||
	test_skip_all "tree state is not where t1118 leaves it"

cleanup()
{
	tree_registry_stop
	if [ -e "$SKIP_PIN" ]; then
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

tree_configure stable
tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'a re-sync of the applied publication changes nothing' '
	tree_sync "$WORK/first.json" &&
	[ "$(report_field selected <"$WORK/first.json")" = 0 ] &&
	[ "$(report_field skipped <"$WORK/first.json")" = 0 ] &&
	[ "$(report_field applied <"$WORK/first.json")" = 0 ] &&
	[ "$(report_field last_seq <"$WORK/first.json")" = 2 ] &&
	[ -e "$MATCH_PIN" ] &&
	[ ! -e "$SKIP_PIN" ] &&
	! grep -q "/v2/shirudo/tree-" "$WORK/requests.log"
'

test_expect_success 'the next generation applies only its appended operation' '
	tree_configure updated &&
	: >"$WORK/requests.log" &&
	tree_sync "$WORK/second.json" &&
	[ "$(report_field selected <"$WORK/second.json")" = 1 ] &&
	[ "$(report_field skipped <"$WORK/second.json")" = 0 ] &&
	[ "$(report_field applied <"$WORK/second.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/second.json")" = 3 ] &&
	[ -e "$MATCH_PIN" ] &&
	[ -e "$SKIP_PIN" ]
'

test_expect_success 'an equally built upatch of another name is fetched, not served from the cache' '
	[ "$(find "$CACHE" -name "*.upatch" -type f | wc -l)" = 2 ] &&
	! grep -q "/v2/shirudo/tree-match/" "$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-skip/manifests/sha256:" \
		"$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-skip/blobs/sha256:" "$WORK/requests.log"
'

test_done
