#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9109 -- the whole keepalive pipeline on real data, with no fixture at a
# seam. The operator builds xfs-fix 1.0.0 and 1.1.0 and appends add,
# delete and add to a tree; the fresh edge node (role=edge) and node B
# (role=core) sync it and send quoted keepalives through the backend's
# collector; the backend's tree ingest and sbom-scan jobs load the tree
# and the SBOM of the nodes' image; and node_status and node_vulns give
# each node's health and exposure. A body altered in transit is refused.
# The operator enrolls node B from the names its vTPM's builder recorded
# before it booted, so the backend trusts its key; the edge node, never
# enrolled, stays untrusted.
#
# end2end/host.sh runs it on the host after node A's suite, as root, with
# the keepalive backend it started, the operator key and the two nodes.
# Both nodes run the stock cloud image, so they bind it as declared.

cd "$(dirname "$0")/.."
. ./test-lib.sh

REPO=$(cd .. && pwd)
E2E=${E2E:-$REPO/build/test-vm/end2end}
FIX=$PWD/fixtures/pipeline
S=$REPO/shirudo
H=$PWD/helper/test-otel-map
CHECKS=$PWD/end2end/pipeline_checks.py
REGISTRY=${REGISTRY:-127.0.0.1:15443}
COLLECTOR=${BACKEND_COLLECTOR:-127.0.0.1:14320}
STACK_NAME=${STACK_NAME:-shirudo-end2end}
TREE=oci://$REGISTRY/shirudo/pipeline-tree
RUNTIME=/usr/local/bin/shirudo-runtime
STATE=/var/lib/shirudo/bpm/upatch-tree
CLICKHOUSE_CLIENT="docker exec -i $STACK_NAME-backend-clickhouse clickhouse-client"
export CLICKHOUSE_CLIENT

[ -n "${END2END_BACKEND-}" ] && [ -n "${END2END_KEYS-}" ] ||
	test_skip_all "end2end/host.sh runs it after node A's suite, with a keepalive backend"
BACKEND=$END2END_BACKEND
KEYS=$END2END_KEYS
command -v docker >/dev/null 2>&1 || test_skip_all "no docker"
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ -x "$H" ] || test_skip_all "test-otel-map helper not built"
[ -s "$E2E/ca.pem" ] || test_skip_all "no registry and collector CA in $E2E"
. ./vm/stack-lib.sh
. ./end2end/node-lib.sh
. ./end2end/pipeline-lib.sh
node_wait edge 0 && node_wait b 0 ||
	test_skip_all "the fresh edge node and node B are not up"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The payload_sha256 of the upatch xfs-fix in the package of release $1.
payload() {
	tar -xzf "$W/pkg/$1/xfs-fix-$1.bee" -C "$W/pkg/$1" &&
	"$S" upatch info --json "$W/pkg/$1/xfs-fix-$1/upatches/xfs-fix.upatch" |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])'
}

# Print the rows of node_status, the age of the record aside.
status_rows() {
	ch "SELECT ak_name, status, trust, failed_check,
		arrayMap(l -> replaceRegexpOne(l, 'last record -?[0-9]+ s ago', 'last record'), log),
		last_seen, generation, last_seq, head_seq, loaded, set_sha256
		FROM shirudo.node_status ORDER BY ak_name"
}

Q_KEEPALIVE="SELECT ak_name, clock, quote, body FROM shirudo.keepalive FINAL
	ORDER BY ak_name, clock FORMAT JSONEachRow"

test_expect_success 'the backend starts empty, with its schema loaded' '
	ch "DROP DATABASE IF EXISTS shirudo SYNC" &&
	ch "DROP DATABASE IF EXISTS otel SYNC" &&
	stack_backend_schema "$BACKEND" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive")" = 0 &&
	test "$(ch "SELECT count() FROM shirudo.tree_ops")" = 0
'

# 1.1.0 differs from 1.0.0 in its program name, so that the two payloads
# differ and the backend has to pick the one the node loaded.
test_expect_success 'the operator builds xfs-fix 1.0.0 and 1.1.0' '
	for v in 1.0.0 1.1.0; do
		mkdir -p "$W/pkg/$v" &&
		cp -R "$FIX/xfs-fix" "$W/pkg/$v/xfs-fix" &&
		ln -s "$REPO/vendor" "$W/pkg/$v/xfs-fix/vendor" &&
		ln -s "$REPO/bpf" "$W/pkg/$v/xfs-fix/bpf" || exit 1
	done &&
	sed -i "s/BPF_PROG(xfs_fix)/BPF_PROG(xfs_fix_1_1)/" \
		"$W/pkg/1.1.0/xfs-fix/xfs-fix.bpf.c" &&
	for v in 1.0.0 1.1.0; do
		(cd "$W/pkg/$v" && "$S" bpm build xfs-fix --version "$v" \
			--keys-dir "$KEYS") >&2 &&
		payload "$v" >"$W/payload-$v" || exit 1
	done &&
	! cmp -s "$W/payload-1.0.0" "$W/payload-1.1.0"
'

test_expect_success 'the operator appends add 1.0.0, delete 1.0.0 and add 1.1.0' '
	"$S" bpm tree append "$W/pkg/1.0.0/xfs-fix-1.0.0.bee" "$TREE" \
		--keys-dir "$KEYS" --tree-id pipeline >&2 &&
	"$S" bpm tree append "$W/pkg/1.0.0/xfs-fix-1.0.0.bee" "$TREE" \
		--keys-dir "$KEYS" --tree-id pipeline --op delete >&2 &&
	"$S" bpm tree append "$W/pkg/1.1.0/xfs-fix-1.1.0.bee" "$TREE" \
		--keys-dir "$KEYS" --tree-id pipeline >&2 &&
	"$S" bpm tree show "$TREE" --cert "$KEYS/cert.der" >"$W/show.json"
'

test_expect_success 'the ingest job loads the publication with its fixes' '
	"$BACKEND/jobs/tree-ingest" --shirudo "$S" --cert "$KEYS/cert.der" \
		"$TREE" >&2 &&
	test "$(ch "SELECT tree_id, generation, head_seq FROM shirudo.tree_pubs FINAL")" = \
		"$(printf "pipeline\t3\t3")" &&
	printf "1\tadd\txfs-fix\n2\tdelete\txfs-fix\n3\tadd\txfs-fix\n" >"$W/ops" &&
	ch_cmp "SELECT seq, op, id FROM shirudo.tree_ops FINAL
		WHERE tree_id = '\''pipeline'\'' ORDER BY seq" "$W/ops" &&
	printf "%s\txfs-fix\tEXAMPLE-0101\tfixes\n" 1 3 >"$W/fixes" &&
	ch_cmp "SELECT seq, id, advisory, source FROM shirudo.upatch_fixes FINAL
		ORDER BY seq" "$W/fixes" &&
	ch "SELECT operation_digest FROM shirudo.tree_ops FINAL
		WHERE tree_id = '\''pipeline'\'' ORDER BY seq" >"$W/digests" &&
	python3 -c "import json, sys
show = json.load(open(sys.argv[1]))
ops = show[\"document\"][\"operations\"]
print(\"\\n\".join(op[\"operation_digest\"].removeprefix(\"sha256:\") for op in ops))
" "$W/show.json" >"$W/published" &&
	diff -u "$W/published" "$W/digests" >&2
'

test_expect_success 'both nodes trust the CA and reach the registry' '
	node_reach edge &&
	node_reach b
'

test_expect_success 'the sync applies 01 01 01 on the edge node and 10 10 10 on node B' '
	unit_ok edge shirudo-bpm-tree-sync.service &&
	unit_ok b shirudo-bpm-tree-sync.service &&
	node_view edge &&
	node_view b &&
	python3 - "$W/view-edge" "$W/view-b" <<-\PY
	import json, sys
	edge, b = (json.load(open(path)) for path in sys.argv[1:3])
	for view in edge, b:
	    assert view["last_seq"] == 3 and view["generation"] == 3, view
	assert edge["outcomes"] == [1, 1, 1], edge
	assert b["outcomes"] == [2, 2, 2], b
	assert b["projection_root"] == "0" * 64, b
	PY
'

test_expect_success 'each node sends two quoted keepalives, a few seconds apart' '
	unit_ok edge shirudo-keepalive.service &&
	unit_ok b shirudo-keepalive.service &&
	sleep 3 &&
	unit_ok edge shirudo-keepalive.service &&
	unit_ok b shirudo-keepalive.service &&
	ch_wait "SELECT count() FROM shirudo.keepalive FINAL" 4 &&
	ak_record edge &&
	ak_record b &&
	test "$(ak edge)" != "$(ak b)"
'

test_expect_success 'node B keeps the attestation key its builder recorded' '
	test -n "$(node_builder_name b ak)" &&
	test "$(ak b)" = "$(node_builder_name b ak)"
'

test_expect_success 'the operator enrolls node B from its builder'\''s records' '
	"$BACKEND/jobs/enroll-put" "$NODES_DIR/node-b/enroll.json" >&2 &&
	test "$(ch "SELECT ek_name FROM shirudo.enrollments FINAL
		WHERE ak_name = '\''$(node_builder_name b ak)'\''")" = "$(node_builder_name b ek)"
'

test_expect_success 'the backend keeps node B enrolled, the edge node untrusted, and every record' '
	{ printf "%s\tenrolled\n" "$(ak b)" &&
	  printf "%s\tuntrusted\n" "$(ak edge)"; } | sort >"$W/nodes" &&
	ch_cmp "SELECT ak_name, max(trust) FROM shirudo.nodes
		GROUP BY ak_name ORDER BY ak_name" "$W/nodes" &&
	test "$(ch "SELECT count() FROM shirudo.rejected")" = 0 &&
	ch "$Q_KEEPALIVE" >"$W/records" &&
	python3 "$CHECKS" quotes "$W/records" | cut -d " " -f 1 | uniq -c |
		awk "{ print \$1 }" >"$W/per-node" &&
	test "$(cat "$W/per-node")" = "$(printf "2\n2")" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive_latest AS l FINAL
		INNER JOIN (SELECT ak_name, max(clock) AS newest, argMax(body, clock) AS newest_body
		            FROM shirudo.keepalive FINAL GROUP BY ak_name) AS k
		ON k.ak_name = l.ak_name AND k.newest = l.clock AND k.newest_body = l.body")" = 2
'

test_expect_success 'node_status shows both nodes healthy, node B enrolled, with the masks VA== and qA==' '
	version=$(on edge "$RUNTIME version --version-id") &&
	test "$version" = "$(on b "$RUNTIME version --version-id")" &&
	ch "INSERT INTO shirudo.expected_builds (version_id, note)
		VALUES ('\''$version'\'', '\''t9109'\'')" &&
	refresh node_status_mv node_vulns_mv &&
	{ printf "%s\thealthy\tenrolled\t0\n" "$(ak b)" &&
	  printf "%s\thealthy\tuntrusted\t0\n" "$(ak edge)"; } | sort >"$W/status" &&
	ch_cmp "SELECT ak_name, status, trust, failed_check FROM shirudo.node_status
		ORDER BY ak_name" "$W/status" &&
	status_log edge >"$W/log-edge" &&
	status_log b >"$W/log-b" &&
	root=$(python3 -c "import json, sys; print(json.load(open(sys.argv[1]))[\"projection_root\"][:8])" \
		"$W/view-edge") &&
	grep -qx "4 chain: pass, root $root" "$W/log-edge" &&
	grep -qx "5 head: pass, seq 3 of 3, generation 3" "$W/log-edge" &&
	grep -qx "6 set: pass, 1 loaded" "$W/log-edge" &&
	grep -qx "4 chain: pass, root 00000000" "$W/log-b" &&
	grep -qx "5 head: pass, seq 3 of 3, generation 3" "$W/log-b" &&
	grep -qx "6 set: pass, 0 loaded" "$W/log-b" &&
	test "$(ch "SELECT mask FROM shirudo.keepalive_latest FINAL
		WHERE ak_name = '\''$(ak edge)'\''")" = VA== &&
	test "$(ch "SELECT mask FROM shirudo.keepalive_latest FINAL
		WHERE ak_name = '\''$(ak b)'\''")" = qA==
'

test_expect_success 'the backend holds what each node recorded and loaded' '
	ch "SELECT operation_digest FROM shirudo.tree_ops FINAL
		WHERE tree_id = '\''pipeline'\'' ORDER BY seq" >"$W/digests" &&
	python3 "$CHECKS" roots $(cat "$W/digests") >"$W/roots" &&
	for n in edge b; do
		on "$n" "$RUNTIME status --keepalive" >"$W/keepalive-$n" &&
		on "$n" "$RUNTIME upatch list --json" >"$W/upatches-$n" &&
		python3 "$CHECKS" set "$W/upatches-$n" >"$W/set-$n" &&
		ch "SELECT projection_root, set_sha256, mask, last_seq, generation
			FROM shirudo.keepalive_latest FINAL
			WHERE ak_name = '\''$(ak "$n")'\'' FORMAT JSONEachRow" >"$W/latest-$n" &&
		python3 - "$n" "$W/latest-$n" "$W/view-$n" "$W/keepalive-$n" \
			"$W/set-$n" "$W/roots" "$W/digests" \
			"$(cat "$W/payload-1.1.0")" <<-\PY || exit 1
		import hashlib, json, sys
		n = sys.argv[1]
		latest, view, body = (json.load(open(p)) for p in sys.argv[2:5])
		listed = open(sys.argv[5]).read().strip()
		projection, history = open(sys.argv[6]).read().split()
		digests = open(sys.argv[7]).read().split()
		payload = sys.argv[8]
		assert latest["projection_root"] == view["projection_root"], (latest, view)
		assert view["outcome_root"] == view["projection_root"], view
		assert latest["mask"] == view["mask"], (latest, view)
		assert latest["set_sha256"] == body["set_sha256"] == listed, (latest, body, listed)
		assert (latest["last_seq"], latest["generation"]) == (3, 3), latest
		assert view["history_root"] == history, (view, history)
		if n == "edge":
		    assert view["chained"] == digests, (view, digests)
		    assert view["projection_root"] == projection, (view, projection)
		    text = f"{payload} xfs-fix\n".encode()
		    assert listed == hashlib.sha256(text).hexdigest(), listed
		else:
		    assert view["chained"] == [], view
		    assert listed == hashlib.sha256(b"").hexdigest(), listed
		PY
	done
'

# The image.json of the nodes' image names no sbom_format, so that its ok
# says the job read it as cyclonedx-json. Each other image is of another
# version, which no node runs.
test_expect_success 'the sbom-scan job reads every state of the SBOM store' '
	image_id=$(sed -n "s/^IMAGE_ID=//p" vm/files/end2end.os-release) &&
	image_version=$(sed -n "s/^IMAGE_VERSION=//p" vm/files/end2end.os-release) &&
	test "$(ch "SELECT DISTINCT image_id, image_version, image_root
		FROM shirudo.keepalive_latest FINAL")" = \
		"$(printf "%s\t%s\t\\\\N" "$image_id" "$image_version")" &&
	python3 - "$W/store" "$FIX/sbom.cdx.json" "$image_id" "$image_version" <<-\PY &&
	import hashlib, json, os, sys
	store, sbom, image_id, version = sys.argv[1:5]
	data = open(sbom, "rb").read()
	sha = hashlib.sha256(data).hexdigest()
	not_cdx = b"{\"spdxVersion\": \"SPDX-2.3\"}\n"
	images = {
	    version: (data, sha, None),
	    "end2end-hash": (data, "0" * 64, "cyclonedx-json"),
	    "end2end-missing": (None, sha, "cyclonedx-json"),
	    "end2end-parse": (not_cdx, hashlib.sha256(not_cdx).hexdigest(), "cyclonedx-json"),
	    "end2end-spdx": (data, sha, "spdx-json"),
	}
	for name, (body, digest, sbom_format) in images.items():
	    where = os.path.join(store, image_id, name, "-")
	    os.makedirs(where)
	    meta = {"image_id": image_id, "image_version": name, "image_root": "",
	            "sbom_sha256": digest, "built_at": "2026-11-12T08:00:00Z"}
	    if sbom_format:
	        meta["sbom_format"] = sbom_format
	    with open(os.path.join(where, "image.json"), "w") as f:
	        json.dump(meta, f)
	    if body is not None:
	        with open(os.path.join(where, "sbom.cdx.json"), "wb") as f:
	            f.write(body)
	PY
	"$BACKEND/jobs/sbom-scan" --store "file://$W/store" --trivy "$FIX/trivy" >&2 &&
	sha=$(sha256sum "$FIX/sbom.cdx.json" | cut -d " " -f 1) &&
	cat >"$W/images" <<-EOF &&
	$image_version	cyclonedx-json	ok	$sha
	end2end-hash	cyclonedx-json	hash_mismatch	-
	end2end-missing	cyclonedx-json	missing	-
	end2end-parse	cyclonedx-json	parse_error	-
	end2end-spdx	spdx-json	unsupported_format	-
	EOF
	ch_cmp "SELECT image_version, sbom_format, state,
		if(empty(sbom_sha256), '\''-'\'', sbom_sha256)
		FROM shirudo.sbom_images FINAL ORDER BY image_version" "$W/images" &&
	test "$(ch "SELECT sbom_sha256, vuln_id, package FROM shirudo.sbom_vulns")" = \
		"$(printf "%s\tEXAMPLE-0202\topenssl" "$sha")"
'

test_expect_success 'node_vulns shields the edge node and excludes node B' '
	stack_backend_client --query "INSERT INTO shirudo.kernel_vulns FORMAT JSONEachRow" \
		<"$FIX/kernel-vulns.json" &&
	test "$(ch "SELECT countIf(kver(kernel_release) >= [7, 0])
		FROM shirudo.keepalive_latest FINAL")" = 2 &&
	refresh node_status_mv node_vulns_mv &&
	cat >"$W/vulns" <<-EOF &&
	b	declared	kernel	EXAMPLE-0101	linux	shield_excludes_node	xfs-fix	3	add	fixes
	b	declared	sbom	EXAMPLE-0202	openssl	exposed_no_shield		0		none
	edge	declared	kernel	EXAMPLE-0101	linux	shielded	xfs-fix	3	add	fixes
	edge	declared	sbom	EXAMPLE-0202	openssl	exposed_no_shield		0		none
	EOF
	ch_cmp "SELECT if(ak_name = '\''$(ak edge)'\'', '\''edge'\'', '\''b'\'') AS node,
		binding, source, vuln_id, package, exposure, upatch_id, applied_seq,
		applied_op, shield_link
		FROM shirudo.node_vulns ORDER BY node, vuln_id" "$W/vulns"
'

test_expect_success 'a record replayed with one body byte changed is body_mismatch' '
	status_rows >"$W/status-before" &&
	ch "$Q_KEEPALIVE" >"$W/records" &&
	grep "\"ak_name\":\"$(ak edge)\"" "$W/records" >"$W/records-edge" &&
	python3 "$CHECKS" replay "$W/records-edge" "$W/quote" "$W/altered" &&
	OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE="$E2E/ca.pem" \
		"$H" send-keepalive "https://$COLLECTOR" ok "$W/altered" \
		"$(cat "$W/quote")" &&
	ch_wait "SELECT count() FROM shirudo.rejected" 1 &&
	test "$(ch "SELECT reason, lower(hex(SHA256(body))) FROM shirudo.rejected")" = \
		"$(printf "body_mismatch\t%s" "$(sha256sum "$W/altered" | cut -d " " -f 1)")" &&
	test "$(ch "SELECT count() FROM shirudo.keepalive FINAL")" = 4 &&
	refresh node_status_mv node_vulns_mv &&
	status_rows >"$W/status-after" &&
	diff -u "$W/status-before" "$W/status-after" >&2
'

test_done
