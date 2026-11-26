#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/run-target-tests.sh [-t <regex>] <family> -- the target tests (t?1??) of one
# family in number order, in the test VM that family booted for itself.
# A test that skips as a whole fails the family: every one is required.
# The image-reboot family runs twice, before and after a reboot of its VM,
# and its tests read which from SHIRUDO_TEST_BOOT, 1 or 2.

set -eu
cd "$(dirname "$0")"
. ./test-filter.sh
family=${1:?usage: run-target-tests.sh [-t <regex>] <family>}
case "$family" in
end2end) dir=end2end ;;
*) dir=functional/$family ;;
esac
[ -d "$dir" ] || {
	printf 'no test family %s\n' "$family" >&2
	exit 1
}
: "${SHIRUDO_BIN:?runtime command is required}"
: "${SHIRUDO_TEST_FIXTURES_DIR:?signed upatch fixtures are required}"
: "${SHIRUDO_TEST_KEY_FIXTURES:?signed image fixtures are required}"
: "${SHIRUDO_TEST_RESULTS:=/tmp/shirudo-verity-results}"
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
[ "$(id -u)" = 0 ] && [ -x "$SHIRUDO_BIN" ] &&
	[ -e /run/shirudo/bpffs/task_authority ] &&
	mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config || {
	printf 'target tests require an initialized dm-verity target\n' >&2
	exit 1
}
for name in config-boot-keys config-live-new-key config-a config-b config-bad config-revoke \
	config-tree-stable config-tree-updated config-tree-deleted config-tree-restored \
	config-otel config-jsonl config-jsonl-bad config-interrupted config-end2end; do
	for suffix in img verity roothash p7s; do
		[ -s "$SHIRUDO_TEST_KEY_FIXTURES/$name.$suffix" ] &&
			[ -s "/var/lib/shirudo/images/$name.$suffix" ] || {
			printf 'missing required image fixture: %s.%s\n' "$name" "$suffix" >&2
			exit 1
		}
	done
done
mkdir -p "$SHIRUDO_TEST_RESULTS"
export SHIRUDO_BIN SHIRUDO_TEST_KEY_FIXTURES
export SHIRUDO_TEST_CONFIG_RESULTS="$SHIRUDO_TEST_RESULTS/config"
export SHIRUDO_TEST_SIGNER_RESULTS="$SHIRUDO_TEST_RESULTS/signers"
export SHIRUDO_TEST_INTERRUPTION_RESULTS="$SHIRUDO_TEST_RESULTS/interruption"
export SHIRUDO_TEST_CLI_RESULTS="$SHIRUDO_TEST_RESULTS/cli"
export SHIRUDO_TEST_REVOKE_RESULTS="$SHIRUDO_TEST_RESULTS/revocation"
export SHIRUDO_TEST_BOOT="${SHIRUDO_TEST_BOOT:-1}"
fail=0
found=0
# Keep post-test log handling in this shell; an end-to-end policy test may
# have attached a hook that denies every new unlabeled executable.
print_test_log()
{
	while IFS= read -r line || [ -n "$line" ]; do
		printf '%s\n' "$line"
	done <"$1"
}

test_log_skipped()
{
	first_line=
	IFS= read -r first_line <"$1" || :
	case "$first_line" in
	'1..0 # SKIP'*) return 0 ;;
	*) return 1 ;;
	esac
}

for t in "$dir"/t[0-9]1[0-9][0-9]-*.sh; do
	[ -e "$t" ] || continue
	found=1
	test_matches "$t" || continue
	# end2end/host.sh runs t9109 to t9114 itself, on the host after node
	# A's suite, against fresh edge nodes and nodes B.
	case "$t" in
	end2end/t9109-pipeline.sh | end2end/t9110-keepalive-history.sh) continue ;;
	end2end/t9111-pipeline-segments.sh | end2end/t9112-activation.sh) continue ;;
	end2end/t9113-shield-rollout.sh | end2end/t9114-app-sandbox.sh) continue ;;
	end2end/t9107-keepalive-backend.sh)
		# host.sh records the example tree when it publishes it to
		# its backend and removes the record when it stops, so a run
		# of the family without host.sh finds none.
		if [ ! -s ../build/test-vm/end2end/backend-tree.digest ]; then
			printf 'not run without a keepalive backend: %s\n' "$t"
			continue
		fi ;;
	esac
	log="$SHIRUDO_TEST_RESULTS/$(basename "$t").log"
	[ "$SHIRUDO_TEST_BOOT" = 1 ] || log="${log%.log}.boot$SHIRUDO_TEST_BOOT.log"
	rc=0
	sh "$t" >"$log" 2>&1 || rc=$?
	print_test_log "$log"
	if test_log_skipped "$log"; then
		printf 'required target test was skipped: %s\n' "$t" >&2
		rc=1
	fi
	if [ "$rc" -ne 0 ]; then
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE"
		fi
	fi
done
[ "$found" -eq 1 ] || {
	printf 'family %s has no target tests\n' "$family" >&2
	exit 1
}
[ "$fail" -eq 0 ]
