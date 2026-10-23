#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Run the complete target-side VM suite. All build/sign work is performed by
# the host bundle builder; target tests consume only prebuilt fixtures.

set -eu

cd "$(dirname "$0")"

# The keyring substitution test deliberately destroys the trust anchor.
# It runs last.
fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in \
	t1200-target-fixtures.sh \
	bpm/t1118-bpm-tree.sh \
	bpm/t1119-bpm-tree-sequential.sh \
	bpm/t1120-bpm-tree-delete.sh \
	tpm/t1102-eventlog-full.sh \
	t1103-version-gate.sh \
	t1104-payload-mismatch.sh \
	t1107-load-unload.sh \
	tpm/t1108-tpm-chain.sh \
	t1111-upatch-get.sh \
	t1114-uprobe-multi.sh \
	otel/t1115-map-export-all.sh \
	otel/t1116-otel-backend.sh \
	otel/t1117-otel-serialized-metric.sh \
	t1122-initrd.sh \
	t1123-keys.sh \
	tamperproof/t1121-bpf-keyring.sh \
	t1124-keys-add.sh \
	t1126-keys-revoke.sh \
	tamperproof/t1101-seal.sh \
	tamperproof/t1132-seal-scratch.sh \
	tamperproof/t1133-seal-init-xattr.sh \
	tamperproof/t1134-seal-task.sh \
	tamperproof/t1105-siggate.sh \
	tamperproof/t1110-lsm-deny.sh \
	tamperproof/t1112-prog-load-keyring-gate.sh \
	tamperproof/t1113-mount-lockdown.sh \
	tamperproof/t1135-pin-rename.sh \
	tamperproof/t1137-bpf-cmd-deny.sh \
	tamperproof/t1136-tamper-counters.sh \
	tamperproof/t1130-map-lockdown.sh \
	tamperproof/t1131-pr-set-mm-identity.sh \
	tamperproof/t1138-secure-exec.sh \
	tamperproof/t1139-traced-exec.sh \
	tamperproof/t1125-key-permission.sh \
	tamperproof/t1132-upatch-integrity.sh \
	t1133-upatch-arena-serializer.sh \
	tamperproof/t1106-keyring-swap.sh
do
	if sh "$t"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

exit "$fail"
