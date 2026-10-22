#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1118 -- pull a signed BPM tree from the fixture OCI registry, select one
# operation, skip another by selector, and fetch only the selected upatch.
# The upatch it applies stays loaded: t1119 and t1120 continue this tree.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
MATCH_CACHE=/var/lib/shirudo/bpm/upatch-tree/artifacts
WORK=$(mktemp -d)

for fixture in \
	"$REGISTRY/shirudo/upatch-tree/manifests/stable" \
	"$FIXTURES/shirudo-test-tree-match.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ ! -e /var/lib/shirudo/bpm/upatch-tree ] ||
	test_skip_all "tree state already exists"

cleanup()
{
	tree_registry_stop
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

tree_configure stable
tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'the publication applies the selected operation' '
	tree_sync "$WORK/report.json" &&
	[ "$(report_field selected <"$WORK/report.json")" = 1 ] &&
	[ "$(report_field skipped <"$WORK/report.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/report.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/report.json")" = 2 ] &&
	[ -e "$MATCH_PIN" ]
'

test_expect_success 'only the selected upatch was fetched and cached' '
	[ "$(find "$MATCH_CACHE" -name "*.upatch" -type f | wc -l)" = 1 ] &&
	grep -q "/v2/shirudo/upatch-tree/manifests/stable" \
		"$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-match/manifests/sha256:" \
		"$WORK/requests.log" &&
	grep -q "/v2/shirudo/tree-match/blobs/sha256:" "$WORK/requests.log" &&
	! grep -q "/v2/shirudo/tree-skip/" "$WORK/requests.log"
'

test_done
