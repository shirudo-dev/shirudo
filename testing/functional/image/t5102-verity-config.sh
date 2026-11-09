#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
verity_required() {
	printf 'Bail out! %s\n' "$*" >&2
	exit 1
}
target_guard

mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config ||
	verity_required "dm-verity image mode is not active"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"
for name in config-a config-b config-bad config-untrusted; do
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
	python3 functional/image/t5102-verity-config.py initial "$work"
'

test_expect_success 'both config certificates are enrolled and frozen' '
	python3 functional/image/t5102-verity-config.py config-keys "$work"
'

test_expect_success 'a config signed by an unapproved certificate leaves state unchanged' '
	python3 functional/image/t5102-verity-config.py untrusted "$work"
'

test_expect_success 'trusted caller without a root nomination gets no CONFIG classification' '
	python3 functional/image/t5102-verity-config.py root-missing "$work"
'

test_expect_success 'trusted caller with a wrong root nomination gets no CONFIG classification' '
	python3 functional/image/t5102-verity-config.py root-wrong "$work"
'

test_expect_success 'exact root nomination classifies CONFIG once and is cleared' '
	python3 functional/image/t5102-verity-config.py root-match "$work"
'

if [ -f "$SHIRUDO_TEST_KEY_FIXTURES/builtin.der" ]; then
	test_expect_success 'kernel built-in trust alone cannot authorize a config signer' '
		python3 functional/image/t5102-verity-config.py builtin "$work"
	'
else
	TAP_COUNT=$((TAP_COUNT + 1))
	printf 'ok %d - built-in config signer # SKIP kernel signing fixture unavailable\n' "$TAP_COUNT"
fi

test_expect_success 'unused data corruption fails before PCR or journal changes' '
	python3 functional/image/t5102-verity-config.py corrupt-data "$work"
'

test_expect_success 'hash padding corruption fails before PCR or journal changes' '
	python3 functional/image/t5102-verity-config.py corrupt-hash "$work"
'

test_expect_success 'a modified root or detached root signature is rejected' '
	python3 functional/image/t5102-verity-config.py corrupt-root "$work" &&
	python3 functional/image/t5102-verity-config.py corrupt-signature "$work"
'

test_expect_success 'config signed by the second key extends PCR once and replaces config' '
	python3 functional/image/t5102-verity-config.py update "$work"
'

test_expect_success 'malformed signed revocation leaves PCR, active mapping and journal unchanged' '
	python3 functional/image/t5102-verity-config.py malformed "$work"
'

test_expect_success 'requesting current CONFIG B is a measured-state no-op' '
	python3 functional/image/t5102-verity-config.py repeat "$work"
'

test_done
