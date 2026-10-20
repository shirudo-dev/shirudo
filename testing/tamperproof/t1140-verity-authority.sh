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

: "${SHIRUDO_TEST_RUNTIME_PROBE:=/run/shirudo/runtime/usr/bin/shirudo-policy-probe}"
: "${SHIRUDO_TEST_TASKS_PIN:=/run/shirudo/bpffs/task_authority}"
[ -x "$SHIRUDO_TEST_RUNTIME_PROBE" ] ||
	verity_required "runtime image has no authority test fixture"
[ -e "$SHIRUDO_TEST_TASKS_PIN" ] ||
	verity_required "image-mode task authority map is not pinned"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
cp "$SHIRUDO_TEST_RUNTIME_PROBE" "$WORK/outside-probe"
chmod +x "$WORK/outside-probe"
printf "invalid executable\n" >"$WORK/invalid-executable"
chmod +x "$WORK/invalid-executable"

# The fixture must be statically linked, or its interpreter and RPATH must
# resolve into the runtime image. It is included only in the test image.
test_expect_success 'an executable on the runtime image receives authority' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" mark "$SHIRUDO_TEST_TASKS_PIN" 1
'
test_expect_success 'fork inherits committed task authority' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" fork "$SHIRUDO_TEST_TASKS_PIN"
'
test_expect_success 'failed exec preserves the running executable authority' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" failed-exec "$SHIRUDO_TEST_TASKS_PIN"
'
test_expect_success 'failed exec after staging an outside image preserves authority' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" failed-exec "$SHIRUDO_TEST_TASKS_PIN" \
		"$WORK/invalid-executable"
'
test_expect_success 'successful exec outside the image clears authority' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" exec "$SHIRUDO_TEST_TASKS_PIN" \
		"$WORK/outside-probe" 0
'
test_expect_success 'successful exec inside the image reevaluates authority' '
	"$WORK/outside-probe" exec "$SHIRUDO_TEST_TASKS_PIN" \
		"$SHIRUDO_TEST_RUNTIME_PROBE" 1
'
test_expect_success 'a copied executable has no image authority' '
	"$WORK/outside-probe" mark "$SHIRUDO_TEST_TASKS_PIN" 0
'
test_expect_success 'trusted tasks reject outside and modified executable mappings' '
	"$SHIRUDO_TEST_RUNTIME_PROBE" mappings "$SHIRUDO_TEST_RUNTIME_PROBE" \
		"$WORK/outside-probe"
'

test_done
