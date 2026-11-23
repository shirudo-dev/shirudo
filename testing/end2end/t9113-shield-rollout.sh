#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9113 -- a shield rolled out and taken back, as an operator does it for
# an advisory against a platform: the java-base64 shield is published to
# a namespace and listed by the backend as available, a new tree takes it
# by its reference and digest, the node pulls it and a JVM a user manager
# starts refuses the crafted input by the guard. The operator then
# deletes it from the tree, as once the platform is fixed, and the node
# retires it: a JVM started after that runs without the guard.
#
# end2end/host.sh runs it on the host after t9111, as root, against a
# third fresh edge node and a registry that holds no tree, with the two
# jars the operator VM built in $E2E/shield.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
S=$REPO/shirudo
CHECKS=$PWD/end2end/pipeline_checks.py
REGISTRY=${REGISTRY:-127.0.0.1:15443}
STACK_NAME=${STACK_NAME:-shirudo-end2end}
NAMESPACE=oci://$REGISTRY/shields
REPOSITORY=shirudo/pipeline-tree
TREE=oci://$REGISTRY/$REPOSITORY
TREE_ID=pipeline-tree
SHIELD=java-base64
VERSION=1.0.0
RUNTIME=/usr/local/bin/shirudo-runtime
STATE=/var/lib/shirudo/bpm/upatch-tree
AGENT=/run/shirudo-java/$SHIELD.jar
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT

[ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
	test_skip_all "end2end/host.sh runs it after t9111, with a keepalive backend"
BACKEND=$END2END_BACKEND
KEYS=$END2END_KEYS
command -v docker >/dev/null 2>&1 || test_skip_all "no docker"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -s "$E2E/ca.pem" ] || test_skip_all "no registry and collector CA in $E2E"
[ -s "$E2E/shield/$SHIELD.jar" ] && [ -s "$E2E/shield/badDecoder.jar" ] ||
	test_skip_all "the operator VM built no jars in $E2E/shield"
. ./vm/stack-lib.sh
. ./end2end/node-lib.sh
. ./end2end/pipeline-lib.sh
node_wait edge 0 || test_skip_all "the fresh edge node is not up"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
# The node mounts the checkout, and E2E with it.
NODE_JAR=/mnt/shirudo-src/${E2E#"$REPO"/}/shield/badDecoder.jar

# The SHA-256 of the jar the node has installed for the shield.
agent_sha256() {
	on edge "sha256sum $AGENT" | cut -d " " -f 1
}

# Run badDecoder in a JVM a user manager of the node starts now, and
# write what it printed to $W/jvm.
jvm() {
	on edge "sh /workspace/shirudo/testing/end2end/guarded-jvm.sh $NODE_JAR" \
		>"$W/jvm"
}

test_expect_success 'the node has followed no tree, and the registry holds no tree and no shield' '
	on edge "[ ! -e $STATE/state.json ] && [ ! -e $STATE/outcomes ]" &&
	on edge "[ ! -e $AGENT ]" &&
	test "$(manifest_status "$REPOSITORY/manifests/stable")" = 404 &&
	test "$(manifest_status shields/bpm-index/manifests/stable)" = 404
'

test_expect_success 'the backend starts empty' '
	ch "DROP DATABASE IF EXISTS shirudo SYNC" &&
	ch "DROP DATABASE IF EXISTS otel SYNC" &&
	stack_backend_schema "$BACKEND" &&
	ch "INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window)
		VALUES (600, 3600, 7)" &&
	version=$(on edge "$RUNTIME version --version-id") &&
	ch "INSERT INTO shirudo.expected_builds (version_id, note)
		VALUES ('\''$version'\'', '\''t9113'\'')" &&
	test "$(ch "SELECT count() FROM shirudo.shield_catalog")" = 0
'

test_expect_success 'the node trusts the CA and reaches the registry' '
	node_reach edge
'

test_expect_success 'without the shield, the JDK refuses the crafted input itself' '
	jvm &&
	grep -q "^badDecoder: no guard, the JDK refused: " "$W/jvm" &&
	grep -qx "status 1" "$W/jvm"
'

# The package is staged without its build.sh, so that put-shields signs
# the jar the operator VM built: the host needs no JDK.
test_expect_success 'the operator publishes the shield, and the backend lists it as available' '
	mkdir -p "$W/pkg/$SHIELD" &&
	cp "$REPO/upatches/$SHIELD/Beefile" "$E2E/shield/$SHIELD.jar" "$W/pkg/$SHIELD/" &&
	SHIRUDO=$S "$REPO/tools/put-shields" --version "$VERSION" --keys-dir "$KEYS" \
		--catalog "$W/shields.json" --new-index "$NAMESPACE" "$W/pkg/$SHIELD" \
		>"$W/append" &&
	read -r _shirudo _bpm _tree _append reference _option digest _rest \
		<"$W/append" &&
	test "$reference" = "$NAMESPACE/$SHIELD:$VERSION" &&
	"$BACKEND/jobs/shields-put" "$W/shields.json" >&2 &&
	printf "%s\t%s\t%s\t%s\n" "$reference" "$SHIELD" "${digest#sha256:}" \
		"['\''CVE-2026-114938'\'']" >"$W/catalog" &&
	ch_cmp "SELECT reference, id, manifest_digest, fixes
		FROM shirudo.shield_catalog FINAL" "$W/catalog" &&
	test "$(ch "SELECT count() FROM shirudo.tree_ops")" = 0
'

test_expect_success 'the operator creates the tree with the shield' '
	tree_append_pushed &&
	test "$(manifest_status "$REPOSITORY/manifests/stable")" = 200 &&
	tree_ingest &&
	printf "%s\t1\tadd\t%s\n" "$TREE_ID" "$SHIELD" >"$W/ops" &&
	ch_cmp "SELECT tree_id, seq, op, id FROM shirudo.tree_ops FINAL
		ORDER BY seq" "$W/ops"
'

test_expect_success 'the node pulls the tree and installs the agent' '
	sync_to 1 1 &&
	sha256sum "$E2E/shield/$SHIELD.jar" | cut -d " " -f 1 >"$W/jar" &&
	test "$(agent_sha256)" = "$(cat "$W/jar")" &&
	on edge "grep -qF -- -javaagent:$AGENT /run/environment.d/shirudo.conf"
'

test_expect_success 'a JVM a user manager starts refuses the crafted input by the guard' '
	jvm &&
	grep -qx "Picked up JAVA_TOOL_OPTIONS: -javaagent:$AGENT" "$W/jvm" &&
	grep -qx "badDecoder: refused by the guard" "$W/jvm" &&
	grep -qx "status 0" "$W/jvm"
'

test_expect_success 'the backend sees the node at the head of the tree, the shield loaded' '
	head_report 1 1
'

test_expect_success 'the operator deletes the shield from the tree' '
	tree_append_pushed delete &&
	tree_ingest &&
	printf "%s\t1\tadd\t%s\n%s\t2\tdelete\t%s\n" "$TREE_ID" "$SHIELD" \
		"$TREE_ID" "$SHIELD" >"$W/ops" &&
	ch_cmp "SELECT tree_id, seq, op, id FROM shirudo.tree_ops FINAL
		ORDER BY seq" "$W/ops"
'

# An unload leaves a jar whose agent does nothing in the place of the
# shield's, for the JVMs that still name it.
test_expect_success 'the node pulls the delete and retires the agent' '
	sync_to 2 "1 2" &&
	sha256sum "$E2E/shield/$SHIELD.jar" | cut -d " " -f 1 >"$W/jar" &&
	retired=$(agent_sha256) &&
	test -n "$retired" && test "$retired" != "$(cat "$W/jar")" &&
	on edge "! grep -qsF -- $AGENT /run/environment.d/shirudo.conf"
'

test_expect_success 'a JVM started after it runs without the guard' '
	jvm &&
	! grep -q "JAVA_TOOL_OPTIONS" "$W/jvm" &&
	grep -q "^badDecoder: no guard, the JDK refused: " "$W/jvm" &&
	grep -qx "status 1" "$W/jvm"
'

test_expect_success 'the backend sees the node at the delete, nothing loaded' '
	head_report 2 0
'

test_done
