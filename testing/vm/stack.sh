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
command=${1:?usage: stack.sh prepare|oci|telemetry|down|vm}
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
	stack_telemetry
	printf 'OTLP: https://%s; ClickHouse: http://%s\n' "$COLLECTOR" "$CLICKHOUSE"
	;;
down) stack_down ;;
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
*) echo "unknown stack command: $command" >&2; exit 2 ;;
esac
