# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# Copyright (c) 2026 Authors of shirudo
#
# testing/integration-lib.sh -- shared setup for target-side tests.
#
# These exercise the LIVE kernel (BPF LSM, kernel keyring, bpffs) and
# the installed binary, so they run as root against a target where `shirudo
# init` has already attached the LSM. shirudo is single-tenant with
# hardcoded paths, so there is no isolation: intended for a dedicated
# throwaway host (the CI vTPM runner) or a developer who has read what
# the test does. The t11xx tests here are all NON-destructive -- they
# assert refusal/denial paths and leave kernel/keyring state untouched.
#
# Sourced after a leading `cd "$(dirname "$0")"` in each test.

INTEGRATION_TESTING_DIR=.
[ -f "$INTEGRATION_TESTING_DIR/test-lib.sh" ] ||
	INTEGRATION_TESTING_DIR=..
. "$INTEGRATION_TESTING_DIR/test-lib.sh"

# Binary under test (the one that init'd the host) and the operator-side
# builder. Overridable for out-of-tree layouts.
: "${SHIRUDO_BIN:=/usr/local/bin/shirudo}"
: "${SHIRUDO_BUILD_BIN:=$INTEGRATION_TESTING_DIR/../tools/shirudo-build/shirudo-build}"

# Skip the whole script unless every precondition holds.
target_guard() {
	[ "$(id -u)" = "0" ] ||
		test_skip_all "target tests must run as root"
	[ -x "$SHIRUDO_BIN" ] ||
		test_skip_all "shirudo binary not executable: $SHIRUDO_BIN"
	[ -e /run/shirudo/bpffs/lsm_link ] ||
		test_skip_all "LSM not attached; run \`shirudo init\` first"
}

# Echo the name of an arbitrary currently-loaded upatch, or "" if none.
first_loaded_upatch() {
	for d in /run/shirudo/bpffs/upatches/*/; do
		[ -e "$d/link" ] || continue
		basename "$d"
		return 0
	done
	return 0
}

# Extract a top-level JSON field from a --report=- document on stdin.
report_field() {
	python3 -c '
import sys, json
raw = sys.stdin.read()
i = raw.find("{")
d = json.loads(raw[i:]) if i >= 0 else {}
print(d.get(sys.argv[1], ""))
' "$1"
}

# The BPM tree tests (t1118-t1120) walk one append-only tree in order:
# the state a sync writes under /var/lib/shirudo is sealed, so a test
# cannot remove it and each one continues from where the previous one
# stopped. These helpers hold what they share.
TREE_STATE_FILE=/var/lib/shirudo/bpm/upatch-tree/state.json
TREE_CONFIG=/etc/shirudo/bpm/upatch-tree.conf
TREE_LABELS=/etc/shirudo/node.labels
TREE_SERVER_PID=

# A top-level field of the recorded tree state, or nothing without one.
tree_state_field() {
	[ -s "$TREE_STATE_FILE" ] || return 0
	report_field "$1" <"$TREE_STATE_FILE"
}

# Point the target at the fixture tree at the given reference.
tree_configure() {
	mkdir -p /etc/shirudo/bpm
	printf 'env=tree-test\n' >"$TREE_LABELS"
	printf '%s\n' \
		'endpoint = oci://127.0.0.1:5443/shirudo/upatch-tree' \
		"reference = $1" >"$TREE_CONFIG"
}

# Serve the fixture registry $1 on 127.0.0.1:5443, logging requests to
# $2/requests.log, and wait for it; tree_registry_stop ends it.
tree_registry_start() {
	python3 ./helper/test-oci-registry.py \
		--root "$1" --port 5443 --log "$2/requests.log" \
		--ready-file "$2/ready" &
	TREE_SERVER_PID=$!
	for _ in 1 2 3 4 5; do
		[ -e "$2/ready" ] && return 0
		sleep 1
	done
	echo "fixture registry did not start" >&2
	exit 1
}

tree_registry_stop() {
	[ -n "$TREE_SERVER_PID" ] || return 0
	kill "$TREE_SERVER_PID" 2>/dev/null || true
	wait "$TREE_SERVER_PID" 2>/dev/null || true
	TREE_SERVER_PID=
}

tree_sync() {
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync --report "$1" >/dev/null
}

# "bpf" once init enrolled the certificate in the kernel's bpf keyring,
# "user" while it is staged in the user keyring.
keyring_mode() {
	"$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_mode
}

# What a load verified against a keyring the caller supplied gets: the
# kernel refuses the keyring outright (EPERM) when the bpf keyring is the
# trust anchor, the admission hook denies it (EACCES) while staging.
foreign_keyring_errno() {
	[ "$(keyring_mode)" = bpf ] && echo 1 || echo 13
}
