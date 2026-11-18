#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7112 -- a Java upatch through the tree: an add installs its jar and
# names it in JAVA_TOOL_OPTIONS under a java_load, and a delete takes the
# agent and the options out again under a java_unload. Runs after t7111,
# on the tree it left.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
NAME=shirudo-test-java
JAR=/run/shirudo-java/$NAME.jar
ARCHIVE=/var/lib/shirudo/upatches/$NAME.upatch
ENV_FILE=/run/environment.d/shirudo.conf
EVENTLOG=/var/lib/shirudo/eventlog
WORK=$(mktemp -d)

for fixture in \
	"$TREE_REPO/manifests/java-added" \
	"$TREE_REPO/manifests/java-deleted" \
	"$FIXTURES/$NAME.jar" \
	"$FIXTURES/$NAME.unload.upatch" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-java-added.img" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-java-deleted.img" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 22 ] &&
	[ ! -e "$ARCHIVE" ] ||
	test_skip_all "tree state is not where t7111 leaves it"

cleanup()
{
	tree_registry_stop
	if [ -e "$ARCHIVE" ]; then
		"$SHIRUDO_BIN" upatch unload "$FIXTURES/$NAME.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	fi
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

# Whether the eventlog holds an event of type $1 for the upatch.
has_event() {
	python3 - "$EVENTLOG" "$1" "$NAME" <<-'PY'
	import json, sys
	for line in open(sys.argv[1], encoding="utf-8"):
	    r = json.loads(line)
	    if r["type"] == sys.argv[2] and \
	       r.get("upatch", {}).get("name") == sys.argv[3]:
	        sys.exit(0)
	sys.exit(1)
	PY
}

tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'an add installs the jar and names it in the options' '
	tree_configure java-added &&
	tree_sync "$WORK/added.json" &&
	[ "$(report_field applied <"$WORK/added.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/added.json")" = 23 ] &&
	cmp "$JAR" "$FIXTURES/$NAME.jar" &&
	grep -qxF "JAVA_TOOL_OPTIONS=\"\${JAVA_TOOL_OPTIONS:+\$JAVA_TOOL_OPTIONS }-javaagent:$JAR\"" "$ENV_FILE" &&
	has_event java_load
'

test_expect_success 'a delete takes the agent and the options out' '
	tree_configure java-deleted &&
	tree_sync "$WORK/deleted.json" &&
	[ "$(report_field applied <"$WORK/deleted.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/deleted.json")" = 24 ] &&
	! cmp -s "$JAR" "$FIXTURES/$NAME.jar" &&
	[ ! -e "$ENV_FILE" ] &&
	[ ! -e "$ARCHIVE" ] &&
	has_event java_unload
'

test_done
