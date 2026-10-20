#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
verity_required() {
	printf 'Bail out! %s\n' "$*" >&2
	exit 1
}
target_guard

mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config ||
	verity_required "dm-verity image mode is not active"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"
for name in config-a config-b config-bad; do
	for suffix in img verity roothash p7s; do
		[ -r "/var/lib/shirudo/images/$name.$suffix" ] ||
			verity_required "missing signed CONFIG fixture: $name.$suffix"
	done
done

# This fixture changes CONFIG and leaves config-b active.
if [ -n "${SHIRUDO_TEST_CONFIG_RESULTS:-}" ]; then
	work=$SHIRUDO_TEST_CONFIG_RESULTS
	mkdir -p "$work"
else
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT HUP INT TERM
fi
export SHIRUDO_BIN

test_expect_success 'current CONFIG and PCR evidence verify' '
	python3 tamperproof/t1154-verity-config.py initial "$work"
'

if [ -f "$SHIRUDO_TEST_KEY_FIXTURES/builtin.der" ]; then
	test_expect_success 'kernel built-in certificate accepts a signed config root' '
		python3 tamperproof/t1154-verity-config.py builtin "$work"
	'
else
	TAP_COUNT=$((TAP_COUNT + 1))
	printf 'ok %d - built-in config signer # SKIP kernel signing fixture unavailable\n' "$TAP_COUNT"
fi

test_expect_success 'unused data corruption fails before PCR or journal changes' '
	python3 tamperproof/t1154-verity-config.py corrupt-data "$work"
'

test_expect_success 'hash padding corruption fails before PCR or journal changes' '
	python3 tamperproof/t1154-verity-config.py corrupt-hash "$work"
'

test_expect_success 'kernel rejects a modified root or detached root signature' '
	python3 tamperproof/t1154-verity-config.py corrupt-root "$work" &&
	python3 tamperproof/t1154-verity-config.py corrupt-signature "$work"
'

test_expect_success 'live CONFIG A to B extends PCR once and replaces config' '
	python3 tamperproof/t1154-verity-config.py update "$work"
'

test_expect_success 'malformed signed revocation leaves PCR, active mapping and journal unchanged' '
	python3 tamperproof/t1154-verity-config.py malformed "$work"
'

test_expect_success 'requesting current CONFIG B is a measured-state no-op' '
	python3 tamperproof/t1154-verity-config.py repeat "$work"
'

test_done
