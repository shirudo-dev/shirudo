#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9107 -- the keepalive backend end to end. end2end/host.sh started the
# backend of tools/backend, with its schema, shirudo-quote-check as
# tpm_quote_check and its collector, and loaded the example tree of
# fixtures/keepalive/ through the backend's tree ingest job and the real
# `bpm tree show`. The target sends the example keepalives of node A and
# node B with their recorded quotes through that collector, and the
# backend's checks give the example's results. A body altered in transit
# is refused, a replayed record collapses and an older record does not
# become a node's latest.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
command -v unshare >/dev/null 2>&1 || test_skip_all "no unshare"

E2E=$PWD/../build/test-vm/end2end
FIX=$PWD/fixtures/keepalive
H=$PWD/helper/test-otel-map
COLLECTOR=https://10.0.2.2:14320
CLICKHOUSE=http://10.0.2.2:18125/
[ -s "$E2E/backend-tree.digest" ] ||
	test_skip_all "no keepalive backend: end2end/host.sh started none"
[ -x "$H" ] || test_skip_all "test-otel-map helper not built"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# Run the query $1 on the backend's ClickHouse and print its result.
ch() {
	python3 - "$CLICKHOUSE" "$1" <<-\PY
	import sys, urllib.request
	opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
	request = urllib.request.Request(sys.argv[1], data=sys.argv[2].encode())
	sys.stdout.write(opener.open(request, timeout=60).read().decode())
	PY
}

# Wait up to 30 seconds for the query $1 to print $2.
ch_wait() {
	i=0
	until [ "$(ch "$1")" = "$2" ]; do
		i=$((i + 1))
		[ "$i" -lt 60 ] || return 1
		sleep 0.5
	done
}

# Compare the query $1's result with file $2.
ch_cmp() {
	ch "$1" >"$2.out" && diff -u "$2" "$2.out" >&2
}

# Field $2 of the row of quotes.tsv for the fixture body $1: 2 attest,
# 3 sig, 4 ak, 5 body_sha256.
quote_field() {
	awk -F '\t' -v name="$1" -v field="$2" '$1 == name { print $field }' \
		"$FIX/quotes.tsv"
}

# The node's key name, 0x000b || SHA-256 of the AK of fixture body $1.
ak_of() {
	python3 -c 'import base64, hashlib, sys
print("000b" + hashlib.sha256(base64.b64decode(sys.argv[1])).hexdigest())' \
		"$(quote_field "$1" 4)"
}

# Field $2 of the clockInfo the quote of fixture body $1 was taken at,
# 0 the TPM clock and 1 the reset count: the u64 and the u32 that follow
# the magic, the type, qualifiedSigner and extraData of TPMS_ATTEST. Each
# capture of the quotes takes others.
clock_info_of() {
	python3 -c 'import base64, struct, sys
a = base64.b64decode(sys.argv[1])
o = 6
for _ in range(2):
    o += 2 + struct.unpack_from(">H", a, o)[0]
print(struct.unpack_from(">QI", a, o)[int(sys.argv[2])])' \
		"$(quote_field "$1" 2)" "$2"
}

# Send the body file $2 with the quote of fixture body $3 through the
# collector, as the host named $1: the record's host.name is the
# sender's, so the sender runs in a UTS namespace of its own.
send() {
	quote="attest=$(quote_field "$3" 2);sig=$(quote_field "$3" 3);ak=$(quote_field "$3" 4)"
	OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$E2E/ca.pem" \
		unshare --uts python3 -c 'import os, socket, sys
socket.sethostname(sys.argv[1])
os.execv(sys.argv[2], sys.argv[2:])' \
		"$1" "$H" send-keepalive "$COLLECTOR" ok "$2" "$quote"
}

refresh() {
	ch 'SYSTEM REFRESH VIEW shirudo.node_status_mv' &&
	ch 'SYSTEM WAIT VIEW shirudo.node_status_mv'
}

AK_A=$(ak_of node-a-1.1.0.json)
AK_B=$(ak_of node-b-1.1.0.json)
CLOCK_A=$(clock_info_of node-a-1.1.0.json 0)
CLOCK_B=$(clock_info_of node-b-1.1.0.json 0)
RESET_A=$(clock_info_of node-a-1.1.0.json 1)
RESET_B=$(clock_info_of node-b-1.1.0.json 1)
DIGEST=$(cat "$E2E/backend-tree.digest")
PARENT=4ee49208ad87695d862c8cc976d1c910170a3de611cfcee2ce181efd8e0a2942
VERSION_ID=d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f

Q_FUNCTION="SELECT count() FROM system.functions WHERE name = 'tpm_quote_check'"
Q_TABLES="SELECT count() FROM system.tables WHERE (database, name) IN
	(('otel', 'otel_logs'), ('shirudo', 'checked'), ('shirudo', 'keepalive'),
	 ('shirudo', 'rejected'), ('shirudo', 'node_status'), ('shirudo', 'tree_ops'))"
Q_PUBS="SELECT tree_id, generation, manifest_digest, parent_manifest_digest,
	head_seq FROM shirudo.tree_pubs FINAL"
Q_OPS="SELECT seq, op, id, selector, repository, manifest_digest, layer_digest,
	payload_sha256, operation_digest FROM shirudo.tree_ops FINAL
	WHERE tree_id = 'fleet-base' ORDER BY seq"
Q_FIXES="SELECT seq, id, advisory, source FROM shirudo.upatch_fixes FINAL
	ORDER BY seq"
Q_BUILD="INSERT INTO shirudo.expected_builds (version_id, note)
	VALUES ('$VERSION_ID', 't9107')"
Q_RECORDS="SELECT count() FROM shirudo.keepalive FINAL"
Q_KEEPALIVE="SELECT host_name, ak_name, reset_count, clock,
	lower(hex(SHA256(body))) FROM shirudo.keepalive FINAL ORDER BY host_name"
Q_STATUS="SELECT node_id, status, trust, failed_check FROM shirudo.node_status
	ORDER BY node_id"
Q_LOG="SELECT node_id,
	replaceRegexpOne(line, 'last record -?[0-9]+ s ago', 'last record N s ago')
	FROM shirudo.node_status ARRAY JOIN log AS line ORDER BY node_id, line"
Q_REJECTED="SELECT reason, host_name, lower(hex(SHA256(body))) FROM shirudo.rejected"
Q_STATUS_A="SELECT status, failed_check FROM shirudo.node_status
	WHERE ak_name = '$AK_A'"
Q_LATEST_A="SELECT clock, generation, last_seq FROM shirudo.keepalive_latest FINAL
	WHERE ak_name = '$AK_A'"
Q_RECORDS_A="SELECT count() FROM shirudo.keepalive FINAL WHERE ak_name = '$AK_A'"

test_expect_success 'the schema is loaded with the quote checker as tpm_quote_check' '
	test "$(ch "$Q_FUNCTION")" = 1 &&
	test "$(ch "$Q_TABLES")" = 6
'

test_expect_success 'the ingest job loaded the publication bpm tree show verified' '
	printf "fleet-base\t3\t%s\t%s\t3\n" "${DIGEST#sha256:}" "$PARENT" \
		>"$W/pubs" &&
	ch_cmp "$Q_PUBS" "$W/pubs" &&
	python3 - "$FIX/tree-1.1.0.json" >"$W/ops" <<-\PY &&
	import json, sys
	def strip(digest):
	    return digest.removeprefix("sha256:")
	for op in json.load(open(sys.argv[1]))["operations"]:
	    a = op["artifact"]
	    print("\t".join([str(op["seq"]), op["op"], op["id"],
	                     json.dumps(op["selector"], separators=(",", ":")),
	                     a["repository"], strip(a["manifest_digest"]),
	                     strip(a["layer_digest"]), strip(a["payload_sha256"]),
	                     strip(op["operation_digest"])]))
	PY
	ch_cmp "$Q_OPS" "$W/ops" &&
	printf "%s\txfs-fix\tEXAMPLE-0101\tfixes\n" 1 3 >"$W/fixes" &&
	ch_cmp "$Q_FIXES" "$W/fixes"
'

test_expect_success 'the checker accepts the keepalives of node A and node B' '
	ch "$Q_BUILD" &&
	send edge-01 "$FIX/node-a-1.1.0.json" node-a-1.1.0.json &&
	send core-01 "$FIX/node-b-1.1.0.json" node-b-1.1.0.json &&
	ch_wait "$Q_RECORDS" 2 &&
	printf "core-01\t%s\t%s\t%s\t%s\nedge-01\t%s\t%s\t%s\t%s\n" \
		"$AK_B" "$RESET_B" "$CLOCK_B" "$(quote_field node-b-1.1.0.json 5)" \
		"$AK_A" "$RESET_A" "$CLOCK_A" "$(quote_field node-a-1.1.0.json 5)" \
		>"$W/keepalive" &&
	ch_cmp "$Q_KEEPALIVE" "$W/keepalive" &&
	test "$(ch "SELECT count() FROM shirudo.rejected")" = 0
'

test_expect_success 'node_status shows node A and node B as the example has them' '
	refresh &&
	printf "core-01\thealthy\tuntrusted\t0\nedge-01\thealthy\tuntrusted\t0\n" \
		>"$W/status" &&
	ch_cmp "$Q_STATUS" "$W/status" &&
	cat >"$W/log" <<-\EOF &&
	core-01	1 signed: pass, untrusted, 0 rejected in the last hour
	core-01	2 fresh: pass, last record N s ago
	core-01	3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build d6d918ad
	core-01	4 chain: pass, root 00000000
	core-01	5 head: pass, seq 3 of 3, generation 3
	core-01	6 set: pass, 0 loaded
	core-01	7 peers: no peers, 1 in group
	edge-01	1 signed: pass, untrusted, 0 rejected in the last hour
	edge-01	2 fresh: pass, last record N s ago
	edge-01	3 reported: pass, verdict ok, cond 0x1555, flags 0, tamper +0, build d6d918ad
	edge-01	4 chain: pass, root 15452248
	edge-01	5 head: pass, seq 3 of 3, generation 3
	edge-01	6 set: pass, 1 loaded
	edge-01	7 peers: no peers, 1 in group
	EOF
	ch_cmp "$Q_LOG" "$W/log"
'

test_expect_success 'a body altered in transit is rejected as body_mismatch' '
	sed "s/\"boot_id\":\"1/\"boot_id\":\"2/" "$FIX/node-a-1.1.0.json" \
		>"$W/altered.json" &&
	! cmp -s "$FIX/node-a-1.1.0.json" "$W/altered.json" &&
	send edge-01 "$W/altered.json" node-a-1.1.0.json &&
	ch_wait "SELECT count() FROM shirudo.rejected" 1 &&
	printf "body_mismatch\tedge-01\t%s\n" \
		"$(sha256sum "$W/altered.json" | cut -d " " -f 1)" >"$W/rejected" &&
	ch_cmp "$Q_REJECTED" "$W/rejected" &&
	test "$(ch "$Q_RECORDS")" = 2 &&
	test "$(ch "$Q_LATEST_A")" = "$(printf "%s\t3\t3" "$CLOCK_A")" &&
	refresh &&
	test "$(ch "$Q_STATUS_A")" = "$(printf "healthy\t0")"
'

# Merges stop so that the replay is seen to arrive before it collapses.
test_expect_success 'a replayed record collapses into the one it repeats' '
	ch "SYSTEM STOP MERGES shirudo.keepalive" &&
	send edge-01 "$FIX/node-a-1.1.0.json" node-a-1.1.0.json &&
	ch_wait "SELECT count() FROM shirudo.keepalive" 3 &&
	test "$(ch "$Q_RECORDS")" = 2 &&
	ch "SYSTEM START MERGES shirudo.keepalive" &&
	ch "OPTIMIZE TABLE shirudo.keepalive FINAL" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive")" = 2
'

test_expect_success 'an older record is kept and does not become the latest' '
	send edge-01 "$FIX/node-a-1.0.0.json" node-a-1.0.0.json &&
	ch_wait "$Q_RECORDS_A" 2 &&
	test "$(ch "$Q_LATEST_A")" = "$(printf "%s\t3\t3" "$CLOCK_A")" &&
	refresh &&
	test "$(ch "$Q_STATUS_A")" = "$(printf "healthy\t0")"
'

test_done
