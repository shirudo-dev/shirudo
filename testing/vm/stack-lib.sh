#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

# registry 3.1.2 and opentelemetry-collector-contrib 0.164.0, both built
# with a Go that offers the hybrid ML-KEM group shirudo requires.
REGISTRY_IMAGE=docker.io/library/registry@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3
COLLECTOR_IMAGE=docker.io/otel/opentelemetry-collector-contrib@sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b
CLICKHOUSE_IMAGE=docker.io/clickhouse/clickhouse-server@sha256:d426d2f612e1e189c90f9a3f8dcd85a03c6851273833817a296bb327e63aa7a7

stack_prepare()
{
	mkdir -p "$W/out"
	chmod 0777 "$W/out"
	install -d -m 0700 "$(dirname "$TLS_DIR")"
	install -d -m 0755 "$TLS_DIR"
	if [ -s "$W/ca.pem" ] && [ -s "$TLS_DIR/server.pem" ] &&
	   [ -s "$TLS_DIR/server.key" ]; then
		return 0
	fi
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$TLS_DIR/ca.key" -out "$W/ca.pem" -days 3650 \
		-subj /CN=shirudo-end2end-ca \
		-addext 'basicConstraints=critical,CA:TRUE' \
		-addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.csr" \
		-subj /CN=shirudo-end2end 2>/dev/null
	printf 'subjectAltName=IP:127.0.0.1,IP:10.0.2.2\n' >"$TLS_DIR/server.ext"
	openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$W/ca.pem" \
		-CAkey "$TLS_DIR/ca.key" -CAcreateserial -out "$TLS_DIR/server.pem" \
		-days 3650 -extfile "$TLS_DIR/server.ext" 2>/dev/null
	rm -f -- "$TLS_DIR/ca.key" "$TLS_DIR/server.csr" \
		"$TLS_DIR/server.ext" "$W/ca.srl"
	chmod 0644 "$TLS_DIR/server.key"
}

stack_wait_https()
{
	attempt=0
	until curl -fsS --max-time 2 --cacert "$W/ca.pem" "$@" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 50 ] || return 1
		sleep 0.2
	done
}

stack_run()
{
	container=$1
	shift
	if docker container inspect "$container" >/dev/null 2>&1; then
		docker start "$container" >/dev/null
	else
		docker run -d --name "$container" "$@" >/dev/null
	fi
}

stack_oci()
{
	set --
	[ "${STACK_PERSIST:-1}" = 0 ] || set -- -v "$W/registry:/var/lib/registry"
	stack_run "$STACK_NAME-registry" "$@" -p "$REGISTRY:5000" \
		-v "$TLS_DIR:/certs:ro" \
		-e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.pem \
		-e REGISTRY_HTTP_TLS_KEY=/certs/server.key "$REGISTRY_IMAGE"
	stack_wait_https "https://$REGISTRY/v2/"
}

stack_telemetry()
{
	docker network inspect "$STACK_NAME" >/dev/null 2>&1 ||
		docker network create "$STACK_NAME" >/dev/null
	set --
	[ "${STACK_PERSIST:-1}" = 0 ] || set -- -v "$W/clickhouse:/var/lib/clickhouse"
	stack_run "$STACK_NAME-clickhouse" "$@" --network "$STACK_NAME" \
		--network-alias clickhouse -p "$CLICKHOUSE:8123" \
		-e CLICKHOUSE_SKIP_USER_SETUP=1 "$CLICKHOUSE_IMAGE"
	attempt=0
	until curl -fsS --max-time 2 --data-binary 'SELECT 1' \
		"http://$CLICKHOUSE/" >/dev/null 2>&1; do
		attempt=$((attempt + 1))
		[ "$attempt" -lt 150 ] || return 1
		sleep 0.2
	done
	stack_run "$STACK_NAME-collector" --network "$STACK_NAME" \
		-p "$COLLECTOR:4318" -v "$TLS_DIR:/certs:ro" \
		-v "$W/out:/out" \
		-v "$REPO/testing/end2end/otelcol.yaml:/etc/otelcol-contrib/config.yaml:ro" \
		"$COLLECTOR_IMAGE"
	stack_wait_https -X POST -H 'Content-Type: application/json' -d '{}' \
		"https://$COLLECTOR/v1/logs"
}

stack_down()
{
	docker logs "$STACK_NAME-collector" >"$W/collector.log" 2>&1 || true
	docker logs "$STACK_NAME-clickhouse" >"$W/clickhouse.log" 2>&1 || true
	docker rm -fv "$STACK_NAME-registry" "$STACK_NAME-collector" \
		"$STACK_NAME-clickhouse" >/dev/null 2>&1 || true
	docker network rm "$STACK_NAME" >/dev/null 2>&1 || true
}
