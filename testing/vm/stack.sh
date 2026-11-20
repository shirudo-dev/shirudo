#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
W=${TEST_VM_STACK_DIR:-$REPO/build/test-vm/stack}
owner=$(stat -c '%u:%g' "$REPO")
checkout=$(printf '%s' "$REPO" | sha256sum | cut -c1-16)
TLS_DIR=${TEST_VM_STACK_PRIVATE_DIR:-/tmp/shirudo-stack-$checkout}/tls
TLS_DIR=$(realpath -m "$TLS_DIR")
STACK_NAME=shirudo-dev
REGISTRY=127.0.0.1:15444
COLLECTOR=127.0.0.1:14319
CLICKHOUSE=127.0.0.1:18124
. "$REPO/testing/vm/stack-lib.sh"
mkdir -p "$W"
if [ "$(id -u)" = 0 ]; then
	touch "$W/.lock"
	chown "$owner" "$W" "$W/.lock"
fi
exec 9>"$W/.lock"
flock 9
case "$TLS_DIR/" in "$REPO/"*) echo 'stack private keys must be outside the checkout' >&2; exit 1 ;; esac
command=${1:?usage: stack.sh prepare|oci|telemetry|down|enroll|sbom|shields|xtop|vm}
shift
prepare()
{
	stack_prepare
	if [ "$(id -u)" = 0 ]; then
		chown "$owner" "$(dirname "$TLS_DIR")" "$TLS_DIR" \
			"$TLS_DIR/server.pem" "$TLS_DIR/server.key" "$W/ca.pem" "$W/out"
	fi
}

case "$command" in
prepare) prepare ;;
oci) prepare; stack_oci; printf 'OCI: oci://%s (CA: %s/ca.pem)\n' "$REGISTRY" "$W" ;;
telemetry)
	prepare
	checker=$REPO/tools/quote-check/shirudo-quote-check
	if [ -x "$checker" ]; then
		stack_telemetry "$REPO/testing/vm/otelcol-stack.yaml" \
			"$REPO/tools/backend" "$checker"
		printf 'OTLP: https://%s; ClickHouse with the backend: http://%s\n' \
			"$COLLECTOR" "$CLICKHOUSE"
	else
		stack_telemetry
		printf 'OTLP: https://%s; ClickHouse: http://%s\n' "$COLLECTOR" "$CLICKHOUSE"
		printf '%s\n' 'no backend: make quote-check, make stack-down, then make telemetry' >&2
	fi
	;;
down)
	case "$W/:$TLS_DIR/" in
	//:* | *://) echo 'refusing to remove a stack at /' >&2; exit 1 ;;
	esac
	stack_down
	# What the containers wrote is theirs, not ours to remove: a
	# container removes it, and then the stack's directory goes.
	if [ -d "$W" ]; then
		docker run --rm -v "$W:/stack" --entrypoint sh "$CLICKHOUSE_IMAGE" \
			-c 'rm -rf /stack/clickhouse /stack/registry /stack/out' ||
			{ echo "cannot remove the data under $W" >&2; exit 1; }
	fi
	rm -rf -- "$W" "$TLS_DIR"
	rmdir -- "$(dirname "$TLS_DIR")" 2>/dev/null || :
	printf 'removed the stack, its data and its CA: %s\n' "$W"
	;;
enroll)
	# Shown before they run, so that a demo shows what each step is: the
	# keys the builder made, then the builds the VMs boot.
	file=$(realpath --relative-to="$REPO" "${1:?usage: stack.sh enroll <enroll.json> [<version_id>...]}")
	shift
	[ "$(docker container inspect -f '{{.State.Running}}' "$STACK_NAME-clickhouse" 2>/dev/null)" = true ] ||
		{ echo 'the local stack is not up: run make stack-up' >&2; exit 1; }
	cd "$REPO"
	client="docker exec -i $STACK_NAME-clickhouse clickhouse-client"
	printf '$ cat %s\n' "$file"
	cat "$file"
	printf "\$ CLICKHOUSE_CLIENT='%s' tools/backend/jobs/enroll-put %s\n" "$client" "$file"
	CLICKHOUSE_CLIENT=$client tools/backend/jobs/enroll-put "$file"
	[ $# -gt 0 ] || exit 0
	printf "\$ CLICKHOUSE_CLIENT='%s' tools/put-shirudo-build --note 'test-vm build' %s\n" "$client" "$*"
	CLICKHOUSE_CLIENT=$client tools/put-shirudo-build --note 'test-vm build' "$@"
	;;
sbom)
	# Shown before they run, as for enroll: each image's SBOM into the
	# store, then the scan that loads what Trivy finds in them, then a
	# refresh of node_vulns, which would show them only at its next
	# scheduled one, up to 5 minutes later.
	[ $# -gt 0 ] && [ $(($# % 3)) -eq 0 ] ||
		{ echo 'usage: stack.sh sbom (<image_id> <image_version> <sbom>)...' >&2; exit 2; }
	[ "$(docker container inspect -f '{{.State.Running}}' "$STACK_NAME-clickhouse" 2>/dev/null)" = true ] ||
		{ echo 'the local stack is not up: run make stack-up' >&2; exit 1; }
	mkdir -p "$W/sbom"
	cd "$REPO"
	client="docker exec -i $STACK_NAME-clickhouse clickhouse-client"
	store=file://$(realpath --relative-to="$REPO" "$W/sbom")
	while [ $# -gt 0 ]; do
		sbom=$(realpath --relative-to="$REPO" "$3")
		printf '$ tools/backend/jobs/sbom-put --store %s --image-id %s --image-version %s %s\n' \
			"$store" "$1" "$2" "$sbom"
		tools/backend/jobs/sbom-put --store "$store" --image-id "$1" \
			--image-version "$2" "$sbom"
		shift 3
	done
	printf "\$ CLICKHOUSE_CLIENT='%s' tools/backend/jobs/sbom-scan --store %s\n" "$client" "$store"
	CLICKHOUSE_CLIENT=$client tools/backend/jobs/sbom-scan --store "$store"
	refresh='SYSTEM REFRESH VIEW shirudo.node_vulns_mv; SYSTEM WAIT VIEW shirudo.node_vulns_mv'
	printf "\$ %s --query '%s'\n" "$client" "$refresh"
	$client --query "$refresh" </dev/null
	;;
shields)
	# Shown before they run, as for enroll: every shield of upatches/
	# pushed to the stack's registry, at a version of its own for each
	# run, as bpm push takes a version once, then the catalog of what was
	# pushed loaded into the backend, where xtop lists the shields as
	# available. The index of the namespace is started on the first run.
	# The arguments name Beefiles and directories of them, every shield
	# under upatches/ when there are none.
	keys=${TEST_VM_HOST_PRIVATE_DIR:?}/operator-keys/keys
	[ -s "$keys/signing_key.pem" ] ||
		{ echo "no operator keys in $keys: run make vm first" >&2; exit 1; }
	for name in registry clickhouse; do
		[ "$(docker container inspect -f '{{.State.Running}}' "$STACK_NAME-$name" 2>/dev/null)" = true ] ||
			{ echo 'the local stack is not up: run make stack-up' >&2; exit 1; }
	done
	stack_clickhouse_client "$STACK_NAME-clickhouse" --query \
		"SELECT name FROM system.databases WHERE name = 'shirudo'" </dev/null | grep -q . ||
		{ echo 'the stack has no backend: make quote-check, make stack-down, then make telemetry' >&2; exit 1; }
	stack_clickhouse_client "$STACK_NAME-clickhouse" --query \
		'EXISTS TABLE shirudo.shield_catalog' </dev/null | grep -qx 1 ||
		{ echo 'the backend has no shirudo.shield_catalog: run make telemetry, which loads its schema' >&2; exit 1; }
	for shield; do
		[ -e "$shield" ] || { echo "no Beefile or directory $shield" >&2; exit 1; }
		set -- "$@" "$(realpath "$shield")"
		shift
	done
	export SHIRUDO="${SHIRUDO:-$REPO/shirudo}"
	export SHIRUDO_BUILD="${SHIRUDO_BUILD:-$REPO/tools/shirudo-build/shirudo-build}"
	[ -x "$SHIRUDO" ] && [ -x "$SHIRUDO_BUILD" ] ||
		{ echo "no $SHIRUDO or $SHIRUDO_BUILD: run make and make shirudo-build" >&2; exit 1; }
	cd "$REPO"
	export BPM_OCI_CA_FILE="$W/ca.pem"
	client="docker exec -i $STACK_NAME-clickhouse clickhouse-client"
	catalog=$(realpath --relative-to="$REPO" "$W/shields.json")
	# A package's member paths must fit in 99 bytes, which a long version
	# breaks, so the version counts the runs. The count is kept beside the
	# registry and goes with it, and is taken before the push, so that a
	# run that fails part way never reuses the version it pushed.
	run=$(($(cat "$W/shields-run" 2>/dev/null || echo 0) + 1))
	printf '%d\n' "$run" >"$W/shields-run"
	new_index=
	curl -sf --cacert "$W/ca.pem" -o /dev/null \
		-H 'Accept: application/vnd.oci.image.manifest.v1+json' \
		"https://$REGISTRY/v2/shields/bpm-index/manifests/stable" ||
		new_index=--new-index
	# shellcheck disable=SC2086 # --new-index or nothing
	set -- --version "1.0.$run" --keys-dir "$keys" --catalog "$catalog" \
		$new_index "oci://$REGISTRY/shields" "$@"
	printf '$ tools/put-shields %s\n' "$*"
	tools/put-shields "$@"
	printf "\$ CLICKHOUSE_CLIENT='%s' tools/backend/jobs/shields-put %s\n" "$client" "$catalog"
	CLICKHOUSE_CLIENT=$client tools/backend/jobs/shields-put "$catalog"
	;;
vm)
	prepare
	export TEST_VM_LOCAL_STACK=1
	export TEST_VM_MAP_EXPORT_CA="$W/ca.pem" TEST_VM_OCI_CA="$W/ca.pem"
	export TEST_VM_MAP_EXPORT_ENDPOINT=https://10.0.2.2:14319
	export TEST_VM_MAP_EXPORT_INSECURE=false
	VM_TENANT=${VM_TENANT:-local}
	export VM_TENANT
	flock -u 9
	exec 9>&-
	exec "$@"
	;;
xtop)
	# Not under the lock: xtop runs until it is quit, while make vm-enroll
	# and the others still have to get it.
	flock -u 9
	exec 9>&-
	# With the operator keys of a bundle from make vm, xtop runs the
	# commands that create a tree itself, against the stack.
	keys=${TEST_VM_HOST_PRIVATE_DIR:-}/operator-keys/keys
	if [ -s "$keys/signing_key.pem" ]; then
		export XTOP_KEYS_DIR="$keys" XTOP_TREE_INGEST="$REPO/tools/backend/jobs/tree-ingest"
		export SHIRUDO="${SHIRUDO:-$REPO/shirudo}"
		export SHIRUDO_BUILD="${SHIRUDO_BUILD:-$REPO/tools/shirudo-build/shirudo-build}"
		export BPM_OCI_CA_FILE="$W/ca.pem"
		export CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-clickhouse clickhouse-client"
	fi
	CLICKHOUSE_URL=${CLICKHOUSE_URL:-http://$CLICKHOUSE/} exec "$REPO/tools/xtop/dist/xtop"
	;;
*) echo "unknown stack command: $command" >&2; exit 2 ;;
esac
