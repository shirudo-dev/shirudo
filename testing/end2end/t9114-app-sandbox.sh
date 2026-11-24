#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9114 -- the app-sandbox upatch through the whole pipeline. The
# operator builds the package of upatches/app-sandbox, with probe.Beefile
# and the rules of fixtures/app-sandbox, which sandbox a program of this
# test and name the programs it may execute by a pattern, publishes it to a namespace, where the backend lists it as
# available, and appends it to a new tree by its reference and digest.
# The node pulls it, and the program then executes, connects and writes
# only what its sandbox allows, while a program outside it is left
# alone. The operator deletes it from the tree, the node unloads it, and
# the program is unrestricted again.
#
# end2end/host.sh runs it on the host last, as root, against a fresh edge
# node of its own and a registry that holds no tree.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
S=$REPO/shirudo
CHECKS=$PWD/end2end/pipeline_checks.py
REGISTRY=${REGISTRY:-127.0.0.1:15443}
STACK_NAME=${STACK_NAME:-shirudo-end2end}
NAMESPACE=oci://$REGISTRY/sandboxes
REPOSITORY=shirudo/pipeline-tree
TREE=oci://$REGISTRY/$REPOSITORY
TREE_ID=pipeline-tree
UPATCH=app-sandbox
VERSION=1.0.0
RUNTIME=/usr/local/bin/shirudo-runtime
STATE=/var/lib/shirudo/bpm/upatch-tree
PINS=/run/shirudo/bpffs/upatches/$UPATCH
# The paths probe.Beefile of fixtures/app-sandbox labels are under it.
APP_DIR=/tmp/shirudo-app-sandbox
PROBE=/workspace/shirudo/testing/end2end/app_sandbox_probe.py
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT

[ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
	test_skip_all "end2end/host.sh runs it last, with a keepalive backend"
BACKEND=$END2END_BACKEND
KEYS=$END2END_KEYS
command -v docker >/dev/null 2>&1 || test_skip_all "no docker"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -s "$E2E/ca.pem" ] || test_skip_all "no registry and collector CA in $E2E"
. ./vm/stack-lib.sh
. ./end2end/node-lib.sh
. ./end2end/pipeline-lib.sh
node_wait edge 0 || test_skip_all "the fresh edge node is not up"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Copy the package directory of upatches/app-sandbox to $W/$1, with the
# headers bpm build looks for beside the Beefile.
stage() {
	mkdir -p "$W/$1" &&
	cp "$REPO/upatches/$UPATCH/Beefile" "$REPO/upatches/$UPATCH/sandbox.toml" \
		"$REPO/upatches/$UPATCH/gen_policy.py" \
		"$REPO/upatches/$UPATCH/$UPATCH.bpf.c" "$W/$1/" &&
	ln -s "$REPO/vendor" "$REPO/bpf" "$W/$1/"
}

# Run the probe in the node with the interpreter $1 and write the checks
# the kernel denied it to $W/denied, one name per line. The probe makes
# 46 checks.
probe() {
	on edge "python3 $PROBE setup $APP_DIR && $1 $PROBE run $APP_DIR" \
		>"$W/probe" &&
	test "$(wc -l <"$W/probe")" = 46 &&
	sed -n "s/ denied\$//p" "$W/probe" >"$W/denied"
}

# The policy bits the node's file $1 is labeled with, in hexadecimal, or
# none for a file without the label.
policy_bits() {
	on edge "python3 -c 'import errno, os, sys
try:
    value = os.getxattr(sys.argv[1], \"security.bpf.shirudo.policy\")
except OSError as error:
    assert error.errno == errno.ENODATA, error
    print(\"none\")
else:
    print(hex(int.from_bytes(value, sys.byteorder)))' $1"
}

test_expect_success 'the node has followed no tree, and the registry holds no tree and no package' '
	on edge "[ ! -e $STATE/state.json ] && [ ! -e $STATE/outcomes ]" &&
	on edge "[ ! -e $PINS ]" &&
	test "$(manifest_status "$REPOSITORY/manifests/stable")" = 404 &&
	test "$(manifest_status sandboxes/bpm-index/manifests/stable)" = 404
'

test_expect_success 'the backend starts empty' '
	ch "DROP DATABASE IF EXISTS shirudo SYNC" &&
	ch "DROP DATABASE IF EXISTS otel SYNC" &&
	stack_backend_schema "$BACKEND" &&
	ch "INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window)
		VALUES (600, 3600, 7)" &&
	version=$(on edge "$RUNTIME version --version-id") &&
	ch "INSERT INTO shirudo.expected_builds (version_id, note)
		VALUES ('\''$version'\'', '\''t9114'\'')" &&
	test "$(ch "SELECT count() FROM shirudo.shield_catalog")" = 0
'

test_expect_success 'the node trusts the CA and reaches the registry' '
	node_reach edge
'

# The application is a copy of the interpreter, so that the label goes on
# a file of this test and python3 itself stays outside the sandbox. The
# pattern helper* matches the name of the link too, whose file it must
# not label.
test_expect_success 'the node has the application and the programs it may and may not execute' '
	on edge "rm -rf $APP_DIR && mkdir $APP_DIR &&
		cp -L /usr/bin/python3 $APP_DIR/app &&
		cp -L /usr/bin/true $APP_DIR/helper-a &&
		cp -L /usr/bin/true $APP_DIR/helper-b &&
		cp -L /usr/bin/true $APP_DIR/other &&
		ln -s other $APP_DIR/helper-link"
'

test_expect_success 'without the sandbox, the application is denied nothing' '
	probe "$APP_DIR/app" &&
	test ! -s "$W/denied"
'

test_expect_success 'the package of upatches/app-sandbox builds with the rules it ships' '
	stage shipped &&
	(cd "$W" && "$S" bpm build shipped --version "$VERSION" \
		--keys-dir "$KEYS") >&2 &&
	"$S" bpm info data "$W/$UPATCH-$VERSION.bee" "upatches/$UPATCH.upatch" \
		>"$W/shipped.data" &&
	grep -qF ".sandboxes = (__u64)3," "$W/shipped.data" &&
	grep -qF ".net_enforced = (__u64)3," "$W/shipped.data"
'

test_expect_success 'a sandbox the Beefile declares no policy for fails the build' '
	stage unknown &&
	printf "[sandbox.nobody]\nexec = []\n" >"$W/unknown/sandbox.toml" &&
	! (cd "$W" && "$S" bpm build unknown --version "$VERSION" \
		--keys-dir "$KEYS") 2>"$W/unknown.err" &&
	grep -qF "the Beefile has no policy nobody" "$W/unknown.err"
'

test_expect_success 'the operator publishes the package, and the backend lists it as available' '
	stage "pkg/$UPATCH" &&
	cp "$PWD/fixtures/$UPATCH/probe.Beefile" "$W/pkg/$UPATCH/Beefile" &&
	cp "$PWD/fixtures/$UPATCH/sandbox.toml" "$W/pkg/$UPATCH/" &&
	SHIRUDO=$S "$REPO/tools/put-shields" --version "$VERSION" --keys-dir "$KEYS" \
		--catalog "$W/shields.json" --new-index "$NAMESPACE" "$W/pkg/$UPATCH" \
		>"$W/append" &&
	read -r _shirudo _bpm _tree _append reference _option digest _rest \
		<"$W/append" &&
	test "$reference" = "$NAMESPACE/$UPATCH:$VERSION" &&
	"$BACKEND/jobs/shields-put" "$W/shields.json" >&2 &&
	printf "%s\t%s\t%s\n" "$reference" "$UPATCH" "${digest#sha256:}" \
		>"$W/catalog" &&
	ch_cmp "SELECT reference, id, manifest_digest
		FROM shirudo.shield_catalog FINAL" "$W/catalog" &&
	test "$(ch "SELECT count() FROM shirudo.tree_ops")" = 0
'

test_expect_success 'the operator creates the tree with the package' '
	tree_append_pushed &&
	test "$(manifest_status "$REPOSITORY/manifests/stable")" = 200 &&
	"$S" bpm tree show "$TREE" --cert "$KEYS/cert.der" >"$W/show.json" &&
	tree_ingest &&
	printf "%s\t1\tadd\t%s\n" "$TREE_ID" "$UPATCH" >"$W/ops" &&
	ch_cmp "SELECT tree_id, seq, op, id FROM shirudo.tree_ops FINAL
		ORDER BY seq" "$W/ops"
'

test_expect_success 'the node pulls the tree, loads the upatch and labels the files its paths and pattern name' '
	sync_to 1 1 &&
	on edge "[ -d $PINS ]" &&
	test "$(policy_bits "$APP_DIR/app")" = 0x1 &&
	test "$(policy_bits "$APP_DIR/helper-a")" = 0x2 &&
	test "$(policy_bits "$APP_DIR/helper-b")" = 0x2 &&
	test "$(policy_bits "$APP_DIR/other")" = none
'

test_expect_success 'the application executes, connects and writes only what its sandbox allows' '
	probe "$APP_DIR/app" &&
	cat >"$W/expected" <<-\EOT &&
	exec-helper-link
	exec-other
	exec-memfd
	connect-remote
	connect-remote-v6
	connect-remote-mapped
	connect-imds
	connect-imds-mapped
	connect-imds-v6
	send-remote
	send-remote-v6
	send-imds
	raw-socket
	vsock-socket
	alg-socket
	unix-docker
	unix-docker-symlink
	create-php
	create-exact
	mkdir-php
	symlink-php
	link-php
	rename-to-php
	rename-from-php
	read-env
	read-ssh-key
	link-env
	rename-ssh-key
	write-php
	truncate-php
	userns-create
	ptrace-other
	EOT
	diff -u "$W/expected" "$W/denied" >&2
'

test_expect_success 'a program outside the sandbox is denied nothing' '
	probe python3 &&
	test ! -s "$W/denied"
'

test_expect_success 'the backend sees the node at the head of the tree, the upatch loaded' '
	head_report 1 1
'

test_expect_success 'the operator deletes the package from the tree' '
	tree_append_pushed delete &&
	tree_ingest &&
	printf "%s\t1\tadd\t%s\n%s\t2\tdelete\t%s\n" "$TREE_ID" "$UPATCH" \
		"$TREE_ID" "$UPATCH" >"$W/ops" &&
	ch_cmp "SELECT tree_id, seq, op, id FROM shirudo.tree_ops FINAL
		ORDER BY seq" "$W/ops"
'

# An unload leaves the labels, which restrict nothing without the upatch.
test_expect_success 'the node pulls the delete and unloads the upatch' '
	sync_to 2 "1 2" &&
	on edge "[ ! -e $PINS ]" &&
	test "$(policy_bits "$APP_DIR/app")" = 0x1
'

test_expect_success 'the application is denied nothing again' '
	probe "$APP_DIR/app" &&
	test ! -s "$W/denied"
'

test_expect_success 'the backend sees the node at the delete, nothing loaded' '
	head_report 2 0
'

test_done
