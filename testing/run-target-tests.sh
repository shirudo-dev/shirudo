#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu
cd "$(dirname "$0")"
: "${SHIRUDO_BIN:?runtime command is required}"
: "${SHIRUDO_TEST_FIXTURES_DIR:?signed upatch fixtures are required}"
: "${SHIRUDO_TEST_KEY_FIXTURES:?signed image fixtures are required}"
: "${SHIRUDO_TEST_RESULTS:=/tmp/shirudo-verity-results}"
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
[ "$(id -u)" = 0 ] && [ -x "$SHIRUDO_BIN" ] &&
	[ -e /run/shirudo/bpffs/task_authority ] &&
	mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config || {
	printf 'image suite requires an initialized dm-verity target\n' >&2
	exit 1
}
for name in config-boot-keys config-live-new-key config-a config-b config-bad config-revoke \
	config-tree-stable config-tree-updated config-tree-deleted config-tree-restored \
	config-otel config-jsonl config-jsonl-bad config-interrupted; do
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
fail=0
# Boot assertions precede updates; the interruption leaves state pending.
for t in \
	tamperproof/t1155-verity-boot-signers.sh \
	tamperproof/t1138-mode-objects.sh \
	t1200-target-fixtures.sh \
	t1122-initrd.sh \
	tamperproof/t1105-siggate.sh \
	t1133-upatch-arena-serializer.sh \
	t1103-version-gate.sh \
	t1104-payload-mismatch.sh \
	t1107-load-unload.sh \
	tpm/t1108-tpm-chain.sh \
	t1111-upatch-get.sh \
	t1114-uprobe-multi.sh \
	bpm/t1118-bpm-tree.sh \
	bpm/t1119-bpm-tree-sequential.sh \
	bpm/t1120-bpm-tree-delete.sh \
	otel/t1115-map-export-all.sh \
	otel/t1116-otel-backend.sh \
	otel/t1117-otel-serialized-metric.sh \
	tamperproof/t1110-lsm-deny.sh \
	tamperproof/t1112-prog-load-keyring-gate.sh \
	tamperproof/t1113-mount-lockdown.sh \
	tamperproof/t1135-pin-rename.sh \
	tamperproof/t1137-bpf-cmd-deny.sh \
	tamperproof/t1136-tamper-counters.sh \
	tamperproof/t1130-map-lockdown.sh \
	tamperproof/t1131-pr-set-mm-identity.sh \
	tamperproof/t1132-seal-scratch.sh \
	tamperproof/t1125-key-permission.sh \
	tamperproof/t1140-verity-authority.sh \
	tamperproof/t1150-verity-devices.sh \
	tamperproof/t1151-verity-process.sh \
	tamperproof/t1153-verity-hidden.sh \
	tamperproof/t1154-verity-config.sh \
	tamperproof/t1157-verity-cli.sh \
	tamperproof/t1156-verity-revocation.sh \
	tamperproof/t1158-verity-interruption.sh
do
	log="$SHIRUDO_TEST_RESULTS/$(basename "$t").log"
	rc=0
	sh "$t" >"$log" 2>&1 || rc=$?
	cat "$log"
	if grep -q '^1\.\.0 # SKIP' "$log"; then
		printf 'required image suite was skipped: %s\n' "$t" >&2
		rc=1
	fi
	if [ "$rc" -ne 0 ]; then
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE"
		fi
	fi
done
[ "$fail" -eq 0 ]
