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
command=${1:?usage: stack.sh prepare|oci|telemetry|down|enroll|xtop|vm}
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
	CLICKHOUSE_URL=${CLICKHOUSE_URL:-http://$CLICKHOUSE/} exec "$REPO/tools/xtop/dist/xtop"
	;;
*) echo "unknown stack command: $command" >&2; exit 2 ;;
esac
