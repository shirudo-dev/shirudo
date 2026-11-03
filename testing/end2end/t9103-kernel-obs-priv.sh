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
ANOMALY_LOAD="$FIXTURES/kernel-obs-cred-anomaly.upatch"
ANOMALY_UNLOAD="$FIXTURES/kernel-obs-cred-anomaly.unload.upatch"
BPF_FILTER_LOAD="$FIXTURES/shirudo-test-map-export.upatch"
BPF_FILTER_UNLOAD="$FIXTURES/shirudo-test-map-export.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
MODPROBE_FILE=/proc/sys/kernel/modprobe
WORK=$(mktemp -d)
. ./end2end/otel-export.sh
otel_setup
MODPROBE_BACKUP="$WORK/kernel.modprobe"
EVENT_PID=

cleanup()
{
	if [ -n "$EVENT_PID" ]; then
		kill "$EVENT_PID" 2>/dev/null || true
		wait "$EVENT_PID" 2>/dev/null || true
	fi
	if [ -e "/run/shirudo/bpffs/upatches/shirudo-test-map-export/link_0" ] ||
	   [ -e "/run/shirudo/bpffs/upatches/shirudo-test-map-export/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$BPF_FILTER_UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	if [ -s "$MODPROBE_BACKUP" ] || [ -e "$MODPROBE_BACKUP" ]; then
		cat "$MODPROBE_BACKUP" >"$MODPROBE_FILE" || true
	fi
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$ANOMALY_UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"
[ -s "$BPF_FILTER_LOAD" ] || test_skip_all "missing BPF filter fixture"
[ -s "$BPF_FILTER_UNLOAD" ] || test_skip_all "missing BPF filter unload fixture"
mkfifo "$WORK/events.in" "$WORK/events.out"
SHIRUDO_TEST_WORK_DIR="$WORK/events" \
	python3 end2end/priv_events.py serve \
		"$WORK/events.in" "$WORK/events.out" "$WORK/expected.json" &
EVENT_PID=$!
exec 3>"$WORK/events.in"
exec 4<"$WORK/events.out"

run_event()
{
	printf '%s\n' "$1" >&3
	IFS= read -r result <&4
	if [ "$result" != ok ]; then
		printf '%s\n' "$result" >&2
		return 1
	fi
}

run_module_request()
{
	[ -w "$MODPROBE_FILE" ] || return 0
	cat "$MODPROBE_FILE" >"$MODPROBE_BACKUP" || return 1
	printf '%s\n' /bin/false >"$MODPROBE_FILE" || return 1
	run_event module-request
	result=$?
	cat "$MODPROBE_BACKUP" >"$MODPROBE_FILE" || return 1
	rm -f "$MODPROBE_BACKUP"
	return "$result"
}

load_observability()
{
	if "$SHIRUDO_BIN" upatch load "$1" --no-precheck --report=- \
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
	otel_export priv "$1"
}

test_expect_success 'kernel-obs upatch loads with the priv serializer' '
	load_observability "$LOAD" &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/priv"
'

test_expect_success 'non-executable mappings do not produce exec protection records' '
	run_event negative &&
	export_priv "$OTEL_OUT/t9103-negative.ndjson" &&
	python3 end2end/priv_events.py check-negative \
		"$OTEL_OUT/t9103-negative.ndjson" "$WORK/expected.json" &&
	export_priv "$OTEL_OUT/t9103-negative-drained.ndjson"
'

test_expect_success 'mprotect does not duplicate an existing executable mapping' '
	run_event existing-exec &&
	export_priv "$OTEL_OUT/t9103-existing-exec.ndjson" &&
	python3 end2end/priv_events.py check-existing-exec \
		"$OTEL_OUT/t9103-existing-exec.ndjson" "$WORK/expected.json" &&
	export_priv "$OTEL_OUT/t9103-existing-exec-drained.ndjson"
'

test_expect_success 'privilege events produce attributed priv records' '
	run_event generate &&
	run_module_request &&
	"$SHIRUDO_BIN" upatch load "$BPF_FILTER_LOAD" --no-precheck \
		--report=- >"$WORK/bpf-filter-load.log" 2>&1 &&
	"$SHIRUDO_BIN" upatch unload "$BPF_FILTER_UNLOAD" --no-precheck \
		>/dev/null &&
	export_priv "$OTEL_OUT/t9103-priv.ndjson" &&
	otel_export exec "$OTEL_OUT/t9103-exec.ndjson" &&
	python3 end2end/priv_events.py \
		check-exec-unknown "$OTEL_OUT/t9103-exec.ndjson" &&
	python3 end2end/priv_events.py check \
		"$WORK/expected.json" "$OTEL_OUT/t9103-priv.ndjson"
'

test_expect_success 'credential anomalies are recorded once per task' '
	[ -s "$ANOMALY_LOAD" ] && [ -s "$ANOMALY_UNLOAD" ] &&
	"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
		>/dev/null &&
	load_observability "$ANOMALY_LOAD" &&
	python3 end2end/priv_events.py anomaly \
		"$WORK/anomaly-expected.json" &&
	export_priv "$OTEL_OUT/t9103-anomaly.ndjson" &&
	python3 end2end/priv_events.py \
		check-anomaly "$WORK/anomaly-expected.json" \
		"$OTEL_OUT/t9103-anomaly.ndjson"
'

test_done
