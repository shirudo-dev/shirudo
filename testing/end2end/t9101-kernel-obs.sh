#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

. ./end2end/kernel-obs-lib.sh
kernel_obs_setup
TABLES="exec net socket listen watch dns priv file"

cleanup()
{
	kernel_obs_unload "$NAME" "$UNLOAD"
	rm -rf "$WORK"
}
trap cleanup EXIT

export_maps()
{
	output="$1"
	for map in $TABLES watch_stat; do
		otel_export "$map" "$output"
	done
}

test_expect_success 'kernel-obs upatch loads with eight serializers' '
	kernel_obs_load "$LOAD" kernel-obs-load.log &&
	for map in $TABLES; do
		[ -e "/run/shirudo/bpffs/upatches/$NAME/serializers/$map" ] ||
			exit 1
	done
'

test_expect_success 'exec, net, listen, DNS, privilege and file events produce records' '
	python3 end2end/kernel_obs_events.py all &&
	python3 end2end/kernel_obs_events.py dns-long &&
	python3 end2end/kernel_obs_events.py dns-many &&
	export_maps "$OTEL_OUT/t9101-events.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9101_check "$OTEL_OUT/t9101-events.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9101_check_events "$OTEL_OUT/t9101-events.ndjson"
'

test_expect_success 'watched destinations are recorded with the metric' '
	python3 end2end/kernel_obs_events.py watch &&
	export_maps "$OTEL_OUT/t9101-watch.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9101_check_watch "$OTEL_OUT/t9101-watch.ndjson"
'

test_expect_success 'an export drains the tables' '
	export_maps "$OTEL_OUT/t9101-drained.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9101_check_drained "$OTEL_OUT/t9101-drained.ndjson"
'

test_expect_success 'only the touched tables carry records' '
	python3 end2end/kernel_obs_events.py exec &&
	export_maps "$OTEL_OUT/t9101-exec-only.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9101_check_exec_only "$OTEL_OUT/t9101-exec-only.ndjson"
'

test_done
