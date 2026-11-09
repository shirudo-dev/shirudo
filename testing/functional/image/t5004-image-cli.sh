#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

H=${SHIRUDO_TEST_IMAGE_CLI_HELPER:-./helper/test-image-cli}
if [ ! -x "$H" ]; then
	printf "not ok 1 - test-image-cli helper is required\n1..1\n"
	exit 1
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
ROOT="$WORK/config"
REG="$ROOT/etc/shirudo/bpm/registries.d"
mkdir -p "$REG" "$ROOT/etc/shirudo/bpm/keys"
printf "eventlog.max_bytes = 12345\n" >"$ROOT/etc/shirudo/shirudo.conf"
printf "authenticated-key\n" >"$ROOT/etc/shirudo/bpm/keys/repo.der"
printf "host-key\n" >"$WORK/host.der"
FP=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

source_file() {
	printf "endpoint = oci://example.invalid\nindex_repository = example/bpm-index\nkey_file = %s\n" \
		"$2" >"$REG/$1.conf"
}

refused() {
	if "$H" "$ROOT" "$@" >"$WORK/output" 2>"$WORK/error"; then
		return 1
	fi
	grep -Eq "image mode:|target:|keys revoke:" "$WORK/error" &&
	grep -q "signed.*config" "$WORK/error"
}

test_expect_success 'local repository mutations fail before changing config or keys' '
	source_file keep "$WORK/host.der" &&
	cp "$REG/keep.conf" "$WORK/before.conf" &&
	refused bpm config register add new oci://example.invalid --cert "$WORK/host.der" &&
	refused bpm config register remove keep &&
	refused bpm config register rm keep &&
	cmp "$REG/keep.conf" "$WORK/before.conf" &&
	grep -qx host-key "$WORK/host.der" &&
	test ! -e "$REG/new.conf"
'

test_expect_success 'local key changes explain signed revocation and reboot enrollment' '
	refused keys add missing.der --vouch missing.vouch &&
	grep -q reboot "$WORK/error" &&
	refused keys revoke "$FP" &&
	grep -q "shirudo image update" "$WORK/error" &&
	refused bpm key add oci://example.invalid/package:latest &&
	grep -q reboot "$WORK/error" &&
	refused bpm key ad missing.der
'

test_expect_success 'read-only repository listing and command help remain available' '
	"$H" "$ROOT" bpm config register list >"$WORK/list" &&
	grep -qx "  keep" "$WORK/list" &&
	"$H" "$ROOT" keys add --help &&
	"$H" "$ROOT" keys revoke --help &&
	"$H" "$ROOT" bpm key add --help &&
	"$H" "$ROOT" bpm key --list-cmds
'

test_expect_success 'config output identifies image settings and authenticated TPM origins' '
	SHIRUDO_TPM_TCTI=attacker SHIRUDO_TPM_OWNER_AUTH=attacker \
		"$H" "$ROOT" config >"$WORK/effective" &&
	grep -q "authenticated config image" "$WORK/effective" &&
	grep -qx "eventlog.max_bytes = 12345" "$WORK/effective" &&
	grep -qx "tpm.tcti = bootstrap-tcti  # from runtime image" "$WORK/effective" &&
	grep -q "15 bytes; redacted; from runtime image" "$WORK/effective" &&
	! grep -q attacker "$WORK/effective"
'

test_expect_success 'repository certificates resolve inside the held config image' '
	source_file relative etc/shirudo/bpm/keys/repo.der &&
	source_file conventional /etc/shirudo/bpm/keys/repo.der &&
	"$H" "$ROOT" source relative >"$WORK/key" &&
	grep -qx authenticated-key "$WORK/key" &&
	"$H" "$ROOT" source conventional >"$WORK/key" &&
	grep -qx authenticated-key "$WORK/key"
'

test_expect_success 'repository certificate references cannot escape to host files' '
	for path in "$WORK/host.der" ../host.der etc/../../host.der; do
		source_file escape "$path" &&
		! "$H" "$ROOT" source escape || exit 1
	done
'

test_expect_success 'tree publications use the active config trusted set' '
	"$H" "$ROOT" tree >"$WORK/certificate" &&
	grep -qx /run/shirudo/runtime/keys/cert.der "$WORK/certificate"
'

test_done
