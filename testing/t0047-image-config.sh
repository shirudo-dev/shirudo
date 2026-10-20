#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

H=${SHIRUDO_TEST_IMAGE_CONFIG_HELPER:-./helper/test-image-config}
[ -x "$H" ] || test_skip_all "test-image-config helper not built"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

source_tree() {
	mkdir -p "$WORK/$1/etc/shirudo/bpm/registries.d" \
		"$WORK/$1/etc/shirudo/bpm/keys" \
		"$WORK/$1/keys/trusted" "$WORK/$1/keys/revoked" &&
	printf "eventlog.max_bytes = 12345\n" >"$WORK/$1/etc/shirudo/shirudo.conf"
}

test_expect_success 'allowed settings are accepted while TPM bootstrap settings survive' '
	source_tree good &&
	"$H" effective "$WORK/good" >"$WORK/effective" &&
	grep -qx "limit=12345" "$WORK/effective" &&
	grep -qx "owner=bootstrap-owner" "$WORK/effective" &&
	grep -qx "tcti=bootstrap-tcti" "$WORK/effective"
'

test_expect_success 'config cannot override runtime, verification key, PCR or TPM bootstrap settings' '
	for key in config.verification_key config.pcr config.image runtime.image runtime.root_hash tpm.owner_auth tpm.tcti; do
		source_tree "$key" &&
		printf "%s = attacker\n" "$key" >>"$WORK/$key/etc/shirudo/shirudo.conf" &&
		! "$H" validate "$WORK/$key" || exit 1
	done
'

test_expect_success 'malformed and oversized config lines are refused' '
	source_tree malformed && printf "not a setting\n" >>"$WORK/malformed/etc/shirudo/shirudo.conf" &&
	! "$H" validate "$WORK/malformed" &&
	source_tree oversized &&
	python3 - "$WORK/oversized/etc/shirudo/shirudo.conf" <<"PY" &&
from pathlib import Path
import sys
Path(sys.argv[1]).write_text("#" + "x" * 2048 + "\n")
PY
	! "$H" validate "$WORK/oversized"
'

test_expect_success 'the main settings file cannot be a symlink outside the verified filesystem' '
	source_tree linked-file &&
	mv "$WORK/linked-file/etc/shirudo/shirudo.conf" "$WORK/outside.conf" &&
	ln -s "$WORK/outside.conf" "$WORK/linked-file/etc/shirudo/shirudo.conf" &&
	! "$H" validate "$WORK/linked-file"
'

test_expect_success 'intermediate directory symlinks cannot escape the verified image' '
	source_tree linked-dir &&
	mv "$WORK/linked-dir/etc" "$WORK/outside-etc" &&
	ln -s "$WORK/outside-etc" "$WORK/linked-dir/etc" &&
	! "$H" validate "$WORK/linked-dir"
'

test_expect_success 'repository and trusted-key symlinks cannot supply mutable outside assets' '
	source_tree linked-assets &&
	printf mutable >"$WORK/outside.der" &&
	ln -s "$WORK/outside.der" "$WORK/linked-assets/etc/shirudo/bpm/keys/repository.der" &&
	! "$H" validate "$WORK/linked-assets" &&
	source_tree linked-trusted &&
	ln -s "$WORK" "$WORK/linked-trusted/keys/trusted/outside" &&
	! "$H" validate "$WORK/linked-trusted"
'

test_expect_success 'special files in config are refused without opening or blocking on them' '
	source_tree fifo && mkfifo "$WORK/fifo/etc/shirudo/bpm/keys/blocked" &&
	! "$H" validate "$WORK/fifo"
'

test_expect_success 'relative lookup refuses absolute paths and parent traversal' '
	"$H" relative "$WORK/good" etc/shirudo/bpm/upatch-tree.conf >"$WORK/relative" &&
	grep -q "^resolved=/proc/self/fd/" "$WORK/relative" &&
	for path in /etc/shirudo/shirudo.conf ../outside.conf etc/../../outside.conf; do
		! "$H" relative "$WORK/good" "$path" || exit 1
	done
'

test_expect_success 'caller environment cannot override authenticated effective TPM settings' '
	SHIRUDO_TPM_OWNER_AUTH=attacker SHIRUDO_TPM_TCTI=attacker \
		"$H" effective "$WORK/good" >"$WORK/env" &&
	grep -qx "owner=bootstrap-owner" "$WORK/env" &&
	grep -qx "tcti=bootstrap-tcti" "$WORK/env"
'

test_expect_success 'invalid export settings fail preparation before activation' '
	for setting in "map_export.otel_insecure = invalid" \
		"map_export.unknown = value" \
		"map_export.otel_retries = -1" \
		"map_export.s3_uri = s3://bucket/key" \
		"map_export.otlp_max_bytes = 1"; do
		source_tree bad-export &&
		printf "%s\n" "$setting" >>"$WORK/bad-export/etc/shirudo/shirudo.conf" &&
		! "$H" validate "$WORK/bad-export" || exit 1
	done
'

test_done
