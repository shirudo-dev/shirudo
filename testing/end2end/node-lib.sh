#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/end2end/node-lib.sh -- reach the other nodes of the end-to-end
# tier as root over SSH: node B (b), which end2end/host.sh boots beside the
# suite's VM, and the fresh edge node (edge), which it boots after. A test
# in node A sources it as it is; on the host, NODES_DIR and NODES_HOST are
# set first.

# Where host.sh records each node, in node-<name>/: port, the host port of
# its SSH server, key, the key of its root, tpm-names, the names of its
# keys its builder recorded, enroll.json, the same as jobs/enroll-put
# loads them, ek-ca.pem, the CA of its endorsement certificate, and ready
# once it is prepared, else failed.
: "${NODES_DIR:=/mnt/shirudo-src/build/test-vm/end2end}"
# Where the nodes' SSH ports are forwarded: QEMU's address for the host,
# as node A sees it.
: "${NODES_HOST:=10.0.2.2}"

# Wait up to $2 seconds, 600 by default, for node $1 to be prepared.
# Fails at once when it did not boot.
node_wait() {
	node_tries=0
	until [ -e "$NODES_DIR/node-$1/ready" ]; do
		[ ! -e "$NODES_DIR/node-$1/failed" ] || return 1
		node_tries=$((node_tries + 1))
		[ "$node_tries" -le "${2:-600}" ] || return 1
		sleep 1
	done
}

# Run the command line ${2...} in node $1's root shell, with this standard
# input and output. The words are joined and parsed again there, as by ssh.
node_sh() {
	node_dir=$NODES_DIR/node-$1
	shift
	ssh -F /dev/null -i "$node_dir/key" -o IdentitiesOnly=yes \
		-o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-p "$(cat "$node_dir/port")" "root@$NODES_HOST" "$@"
}

# The name of the key $2, ak or ek, that node $1's builder recorded before
# the node booted.
node_builder_name() {
	sed -n "s/^$2-name //p" "$NODES_DIR/node-$1/tpm-names"
}
