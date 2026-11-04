# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# Copyright (c) 2026 Authors of shirudo
#
# testing/integration-lib.sh -- shared setup for target-side tests.
#
# These exercise the LIVE kernel (BPF LSM, kernel keyring, bpffs) and
# the installed binary, so they run as root against a target where `shirudo
# init` has already attached the LSM. shirudo is single-tenant with
# hardcoded paths, so there is no isolation: intended for the test VM each
# family of target tests (t?1??) boots, or a developer who has read what
# the test does.
#
# Sourced from testing/, where each test changes to first.

. ./test-lib.sh

# Binary under test, the one that init'd the host; overridable for
# out-of-tree layouts.
: "${SHIRUDO_BIN:=/usr/local/bin/shirudo}"

# Skip the whole script unless every precondition holds.
target_guard() {
	[ "$(id -u)" = "0" ] ||
		test_skip_all "target tests must run as root"
	[ -x "$SHIRUDO_BIN" ] ||
		test_skip_all "shirudo binary not executable: $SHIRUDO_BIN"
	[ -e /run/shirudo/bpffs/lsm_link ] ||
		test_skip_all "LSM not attached; run \`shirudo init\` first"
}

# TPM startup can sleep before the task reaches its blocking FIFO open.
fifo_release() {
	python3 -c '
import errno, os, sys, time
for _ in range(100):
    try:
        fd = os.open(sys.argv[1], os.O_WRONLY | os.O_NONBLOCK)
    except OSError as error:
        if error.errno != errno.ENXIO:
            raise
        time.sleep(0.1)
        continue
    try:
        os.write(fd, b"x")
    finally:
        os.close(fd)
    break
else:
    raise TimeoutError("task did not open the FIFO within ten seconds")
' "$1"
}

# The executable $SHIRUDO_BIN runs: itself, or the one the runtime image's
# wrapper script hands over to.
runtime_binary() {
	if [ "$(head -c 2 "$SHIRUDO_BIN")" = '#!' ]; then
		sed -n 's/^exec \([^ ]*\).*/\1/p' "$SHIRUDO_BIN"
	else
		printf '%s\n' "$SHIRUDO_BIN"
	fi
}

# Load the signed fixture $1 unless it is loaded already: a family's tests
# boot a VM of their own and find loaded only what they load themselves.
require_loaded() {
	[ -d "/run/shirudo/bpffs/upatches/$1" ] ||
		"$SHIRUDO_BIN" upatch load \
			"${SHIRUDO_TEST_FIXTURES_DIR:?}/$1.upatch" >/dev/null 2>&1
	[ -d "/run/shirudo/bpffs/upatches/$1" ]
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

keyring_mode() {
	"$SHIRUDO_BIN" status --json 2>/dev/null | report_field keyring_mode
}

# The BPM tree tests (t7101-t7103) walk one append-only tree in order:
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
	"$SHIRUDO_BIN" image update \
		"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-$1"
}

# Config fixtures are immutable; later tests activate their own signed image.
tree_cleanup_config() { :; }

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

# A sealed kernel BPF keyring refuses caller-supplied trust anchors.
foreign_keyring_errno() {
	echo 1
}
