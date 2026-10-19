#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=kernel-obs
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
MODPROBE_FILE=/proc/sys/kernel/modprobe
WORK=$(mktemp -d)
MODPROBE_BACKUP="$WORK/kernel.modprobe"

cleanup()
{
	if [ -s "$MODPROBE_BACKUP" ] || [ -e "$MODPROBE_BACKUP" ]; then
		cat "$MODPROBE_BACKUP" >"$MODPROBE_FILE" || true
	fi
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"
[ -w "$MODPROBE_FILE" ] || test_skip_all "kernel.modprobe is not writable"

load_observability()
{
	if "$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck --report=- \
		>"$WORK/load.log" 2>&1; then
		return 0
	fi
	cat "$WORK/load.log" >&2
	if [ -d /mnt/shirudo-out ]; then
		cp "$WORK/load.log" /mnt/shirudo-out/kernel-obs-priv-load.log
	fi
	return 1
}

export_priv()
{
	"$SHIRUDO_BIN" upatch map "$NAME" priv --json="$1" >/dev/null
}

test_expect_success 'kernel-obs upatch loads with the priv serializer' '
	load_observability &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/priv"
'

test_expect_success 'non-executable mappings do not produce exec protection records' '
	SHIRUDO_TEST_WORK_DIR="$WORK/events" \
		python3 upatch/kernel-obs/priv/priv_events.py negative &&
	export_priv "$WORK/negative.ndjson" &&
	python3 upatch/kernel-obs/priv/priv_events.py check-negative "$WORK/negative.ndjson"
'

test_expect_success 'privilege events produce attributed priv records' '
	cat "$MODPROBE_FILE" >"$MODPROBE_BACKUP" &&
	printf '%s\n' /bin/false >"$MODPROBE_FILE" &&
	SHIRUDO_TEST_WORK_DIR="$WORK/events" \
		python3 upatch/kernel-obs/priv/priv_events.py generate "$WORK/expected.json" &&
	cat "$MODPROBE_BACKUP" >"$MODPROBE_FILE" &&
	rm -f "$MODPROBE_BACKUP" &&
	export_priv "$WORK/priv.ndjson" &&
	python3 upatch/kernel-obs/priv/priv_events.py check \
		"$WORK/expected.json" "$WORK/priv.ndjson"
'

test_done
