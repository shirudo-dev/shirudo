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
	rm -rf "$WORK"
}
trap cleanup EXIT

test_expect_success 'DNS observations use real loopback UDP traffic' '
	kernel_obs_load "$LOAD" kernel-obs-load.log &&
	python3 end2end/kernel_obs_events.py dns-long &&
	python3 end2end/kernel_obs_events.py dns-many &&
	otel_export dns "$OTEL_OUT/t9104-dns.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9104_check "$OTEL_OUT/t9104-dns.ndjson" &&
	otel_export dns "$OTEL_OUT/t9104-dns-empty.ndjson" &&
	python3 end2end/kernel_obs_checks.py t9104_check_empty "$OTEL_OUT/t9104-dns-empty.ndjson"
'

test_done
