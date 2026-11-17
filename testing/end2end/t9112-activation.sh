#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9112 -- enroll the fresh edge node through credential activation, as
# "Enroll from a target activation" of the attest page does it. Its vTPM
# carries an endorsement certificate from its maker's CA, ek-ca.pem beside
# its records; the operator checks the certificate against that CA, makes a
# challenge, the edge node answers it with a second nonce, and the operator
# verifies the credential and marks the key enrolled in the backend. Node
# B's CA does not vouch for the edge node, and node B refuses the edge
# node's challenge.
#
# end2end/host.sh runs it on the host after t9110, which leaves both
# nodes untrusted and their keepalives in the backend.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
S=$REPO/shirudo
STACK_NAME=${STACK_NAME:-shirudo-end2end}
RUNTIME=/usr/local/bin/shirudo-runtime
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT

[ -n "${END2END_BACKEND-}" ] ||
	test_skip_all "end2end/host.sh runs it after t9110, with a keepalive backend"
command -v docker >/dev/null 2>&1 || test_skip_all "no docker"
command -v jq >/dev/null 2>&1 || test_skip_all "no jq"
. ./vm/stack-lib.sh
. ./end2end/node-lib.sh
. ./end2end/pipeline-lib.sh
node_wait edge 0 && node_wait b 0 ||
	test_skip_all "the fresh edge node and node B are not up"
EDGE_CA=$NODES_DIR/node-edge/ek-ca.pem
B_CA=$NODES_DIR/node-b/ek-ca.pem
[ -s "$EDGE_CA" ] && [ -s "$B_CA" ] ||
	test_skip_all "the nodes' vTPMs carry no endorsement certificate"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The steps run the commands of "Enroll from a target activation" as the
# attest page gives them, the target's in node $1 over SSH.

# Copy the challenge $2 to node $1 and answer it there with the nonce $3,
# into $4.
answer() {
	node_sh "$1" "umask 077 && cat >/root/challenge.json" <"$2" &&
	on "$1" "$RUNTIME attest --nonce=$3 --challenge=/root/challenge.json \
		--output=/root/answer.json && cat /root/answer.json" >"$4"
}

test_expect_success 'the edge node is untrusted before it is enrolled' '
	ak_record edge &&
	test "$(ch "SELECT max(trust) FROM shirudo.nodes
		WHERE ak_name = '\''$(ak edge)'\''")" = untrusted
'

test_expect_success 'the edge node presents its attestation key and endorsement certificate' '
	openssl rand -hex 32 >"$W/nonce" &&
	on edge "$RUNTIME attest --nonce=$(cat "$W/nonce") --output=/root/enroll.json &&
		stat -c %a /root/enroll.json" >"$W/enroll.mode" &&
	test "$(cat "$W/enroll.mode")" = 600 &&
	on edge cat /root/enroll.json >"$W/enroll.json" &&
	jq -r .ak.name "$W/enroll.json" >"$W/ak" &&
	jq -r .ek.name "$W/enroll.json" >"$W/ek" &&
	test "$(cat "$W/ak")" = "$(ak edge)" &&
	test "$(jq -r .ek.type "$W/enroll.json")" = ecc &&
	test "$(jq -r ".ek_certificate | type" "$W/enroll.json")" = string
'

test_expect_success 'a challenge against node B'\''s CA is refused' '
	! "$S" attest challenge --evidence="$W/enroll.json" \
		--ak-name="$(cat "$W/ak")" --ek-ca="$B_CA" \
		--output="$W/challenge-b.json" >"$W/challenge-b.out" &&
	grep -qF "  FAIL  endorsement certificate: chains to $B_CA: " \
		"$W/challenge-b.out" &&
	test ! -e "$W/challenge-b.json"
'

test_expect_success 'the operator makes a challenge the edge node'\''s CA vouches for' '
	"$S" attest challenge --evidence="$W/enroll.json" \
		--ak-name="$(cat "$W/ak")" --ek-ca="$EDGE_CA" \
		--output="$W/challenge.json" >"$W/challenge.out" &&
	grep -qx "  OK    endorsement certificate: describes the endorsement key" \
		"$W/challenge.out" &&
	grep -qx "  OK    endorsement certificate: chains to $EDGE_CA" \
		"$W/challenge.out" &&
	grep -qx "challenge: $W/challenge.json" "$W/challenge.out" &&
	sed -n "s/^credential: //p" "$W/challenge.out" >"$W/credential" &&
	test "$(wc -c <"$W/credential")" = 65
'

test_expect_success 'node B refuses the edge node'\''s challenge, made for another key' '
	openssl rand -hex 32 >"$W/nonce-b" &&
	! answer b "$W/challenge.json" "$(cat "$W/nonce-b")" "$W/answer-b.json" \
		2>"$W/answer-b.err" &&
	grep -q "the challenge was made for another attestation key" "$W/answer-b.err"
'

test_expect_success 'the edge node answers the challenge with a second nonce' '
	openssl rand -hex 32 >"$W/nonce-2" &&
	answer edge "$W/challenge.json" "$(cat "$W/nonce-2")" "$W/answer.json"
'

test_expect_success 'the answer carries the credential made for the edge node'\''s keys' '
	"$S" attest verify --evidence="$W/answer.json" --nonce="$(cat "$W/nonce-2")" \
		--ak-name="$(cat "$W/ak")" --ek-name="$(cat "$W/ek")" \
		--expect-credential="$(cat "$W/credential")" >"$W/verify.out" &&
	grep -qx "  OK    attestation key: activated the credential made for it under the endorsement key" \
		"$W/verify.out" &&
	grep -qx "verdict: ok" "$W/verify.out" &&
	! "$S" attest verify --evidence="$W/answer.json" --nonce="$(cat "$W/nonce-2")" \
		--ak-name="$(cat "$W/ak")" --ek-name="$(cat "$W/ek")" \
		--expect-credential="$(printf "%064d" 0)" >"$W/verify-wrong.out"
'

test_expect_success 'the operator enrolls the edge node, and the backend trusts its key alone' '
	ch "INSERT INTO shirudo.nodes (ak_name, trust)
		VALUES ('\''$(cat "$W/ak")'\'', '\''enrolled'\'')" &&
	refresh node_status_mv &&
	ch "SELECT ak_name, trust FROM shirudo.node_status
		WHERE trust = '\''enrolled'\''" >"$W/enrolled" &&
	printf "%s\tenrolled\n" "$(ak edge)" | diff -u - "$W/enrolled"
'

# t9110 loaded the schema again, which dropped node B's enrollment of
# t9109.
test_expect_success 'node B, whose enrollment went with the schema, stays untrusted' '
	ak_record b &&
	test "$(ch "SELECT trust FROM shirudo.node_status
		WHERE ak_name = '\''$(ak b)'\''")" = untrusted
'

test_done
