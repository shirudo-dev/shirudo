#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

. ./end2end/kernel-obs-lib.sh
kernel_obs_setup

cleanup()
{
	kernel_obs_unload "$NAME" "$UNLOAD"
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT

export_net_maps()
{
	for map in net socket; do
		otel_export "$map" "$OTEL_OUT/t9102-events.ndjson"
	done
}

test_expect_success 'socket map loads with the network serializers' '
	kernel_obs_load "$LOAD" kernel-obs-load.log &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/net" &&
	test -e "/run/shirudo/bpffs/upatches/$NAME/serializers/socket"
'

test_expect_success 'TCP, UDP and additional socket families are recorded' '
	python3 end2end/kernel_obs_events.py tcp &&
	python3 end2end/kernel_obs_events.py udp &&
	python3 end2end/kernel_obs_events.py sockets \
		>"$WORK/expected.json" &&
	export_net_maps &&
	python3 end2end/kernel_obs_checks.py t9102_check "$WORK/expected.json" \
		"$OTEL_OUT/t9102-events.ndjson"
'

test_done
