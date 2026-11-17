#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/end2end/pipeline-lib.sh -- what the host tests of the keepalive
# pipeline, t9109 to t9112, do to the nodes, the registry and the
# backend's ClickHouse. A test sets W, CHECKS, STATE, RUNTIME, E2E and
# STACK_NAME, and TREE_ID and WINDOW where it uses them, and sources
# node-lib.sh and stack-lib.sh first.

# Run the query $1 on the backend's ClickHouse and print its result.
ch() {
	stack_backend_client --query "$1" </dev/null
}

# Wait up to 60 seconds for the query $1 to print $2.
ch_wait() {
	i=0
	until [ "$(ch "$1")" = "$2" ]; do
		i=$((i + 1))
		[ "$i" -lt 120 ] || return 1
		sleep 0.5
	done
}

# Compare the query $1's result with file $2.
ch_cmp() {
	ch "$1" >"$2.out" && diff -u "$2" "$2.out" >&2
}

# Refresh the views $@ of shirudo, one after the other.
refresh() {
	for view in "$@"; do
		ch "SYSTEM REFRESH VIEW shirudo.$view" &&
		ch "SYSTEM WAIT VIEW shirudo.$view" || return 1
	done
}

# Run the command line ${2...} as root in node $1, edge or b, with no
# standard input.
on() {
	node_sh "$@" </dev/null
}

# Start the unit $2 in node $1 and wait for it; its journal is what a
# failure needs.
unit_ok() {
	on "$1" "systemctl start $2 ||
		{ journalctl -u $2 --no-pager | tail -n 30 >&2; exit 1; }"
}

# Make node $1 trust the registry's and collectors' CA and reach the
# registry at 127.0.0.1:15443, where the tree names its packages.
node_reach() {
	node_sh "$1" "cat >/etc/shirudo/end2end-ca.pem" <"$E2E/ca.pem" &&
	on "$1" "install -d /etc/shirudo/bpm &&
		echo BPM_OCI_CA_FILE=/etc/shirudo/end2end-ca.pem \
			>/etc/shirudo/bpm/environment &&
		echo OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/end2end-ca.pem \
			>/etc/shirudo/map-export.env &&
		cd /workspace/shirudo/testing && rm -f /tmp/forward-ready &&
		setsid -f python3 end2end/tcp_forward.py 127.0.0.1:15443 \
			10.0.2.2:15443 /tmp/forward-ready \
			</dev/null >/dev/null 2>&1 &&
		i=0 && until [ -e /tmp/forward-ready ]; do
			i=\$((i + 1)); [ \$i -lt 50 ] || exit 1; sleep 0.1
		done"
}

# Copy node $1's tree records to $W/<name>-$1 and write its view of them,
# with the keepalive window WINDOW when it is set, to $W/view-$1. A node
# that applied nothing has no tree-eventlog.
node_view() {
	on "$1" cat "$STATE/state.json" >"$W/state.json-$1" &&
	on "$1" cat "$STATE/outcomes" >"$W/outcomes-$1" &&
	on "$1" "[ ! -e $STATE/tree-eventlog ] || cat $STATE/tree-eventlog" \
		>"$W/tree-eventlog-$1" &&
	python3 "$CHECKS" node "$W/state.json-$1" "$W/outcomes-$1" \
		"$W/tree-eventlog-$1" ${WINDOW:+"$WINDOW"} >"$W/view-$1"
}

# Print the key $2 of node $1's view.
view() {
	python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' \
		"$W/view-$1" "$2"
}

# Record in $W/ak-$1 the attestation key that node $1's records name.
ak_record() {
	boot=$(on "$1" cat /proc/sys/kernel/random/boot_id) &&
	ch "SELECT DISTINCT ak_name FROM shirudo.keepalive
		WHERE boot_id = '$boot'" >"$W/ak-$1" &&
	test "$(wc -l <"$W/ak-$1")" = 1
}

# The attestation key name of node $1.
ak() {
	cat "$W/ak-$1"
}

# The newest record of node $1: base_seq, base_root, mask and
# projection_root, as its view gives them.
latest_cmp() {
	printf '%s\t%s\t%s\t%s\n' "$(view "$1" base_seq)" "$(view "$1" base_root)" \
		"$(view "$1" mask)" "$(view "$1" projection_root)" >"$W/latest-$1" &&
	ch_cmp "SELECT base_seq, base_root, mask, projection_root
		FROM shirudo.keepalive_latest FINAL
		WHERE ak_name = '$(ak "$1")'" "$W/latest-$1"
}

# node_ops of node $1 in tree TREE_ID against its outcomes, from seq 1 or
# from a gap row at seq $2.
history_cmp() {
	python3 "$CHECKS" history "$W/outcomes-$1" "$2" >"$W/history-$1" &&
	ch_cmp "SELECT seq, code, lower(hex(root)) FROM shirudo.node_ops FINAL
		WHERE ak_name = '$(ak "$1")' AND tree_id = '$TREE_ID'
		ORDER BY seq" "$W/history-$1"
}

# The lines of node $1's log in node_status.
status_log() {
	ch "SELECT line FROM shirudo.node_status ARRAY JOIN log AS line
		WHERE ak_name = '$(ak "$1")'"
}

# Compare ak_name, status and failed_check of node_status with file $1.
# On a difference, print what the backend is torn down with: each node's
# log, the last_seq and tamper array of each of its records, and the
# tamper counters each node reads now.
status_cmp() {
	ch_cmp "SELECT ak_name, status, failed_check
		FROM shirudo.node_status ORDER BY ak_name" "$1" && return 0
	for n in edge b; do
		status_log "$n" | sed "s/^/$n: /" >&2
		ch "SELECT last_seq, tamper FROM shirudo.keepalive FINAL
			WHERE ak_name = '$(ak "$n")' ORDER BY clock" |
			sed "s/^/$n records: /" >&2
		on "$n" "$RUNTIME status" | sed -n "/Tamper attempts/,/^\$/p" |
			sed "s/^/$n status: /" >&2
	done
	return 1
}

# Write the mark $1 to the registry's access log, a GET of a manifest that
# does not exist, and wait up to 10 seconds for it to appear there.
registry_mark() {
	curl -s -o /dev/null --cacert "$E2E/ca.pem" \
		"https://$REGISTRY/v2/end2end-mark/manifests/$1" &&
	i=0 &&
	until stack_oci_log | grep -Fq "/v2/end2end-mark/manifests/$1 "; do
		i=$((i + 1))
		[ "$i" -lt 100 ] || return 1
		sleep 0.1
	done
}

# Print the requests for repository $3 that the registry logged between
# the marks $1 and $2, one "<method> <path>" per line, the path after the
# repository's.
requests() {
	stack_oci_log | python3 "$CHECKS" requests "$1" "$2" "$3"
}
