#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

. ./end2end/otel-export.sh

kernel_obs_setup()
{
	FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
	NAME=kernel-obs
	LOAD="$FIXTURES/$NAME.upatch"
	UNLOAD="$FIXTURES/$NAME.unload.upatch"
	PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
	[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
	[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"
	otel_setup
	WORK=$(mktemp -d)
}

kernel_obs_unload()
{
	if [ -e "/run/shirudo/bpffs/upatches/$1/link_0" ] ||
	   [ -e "/run/shirudo/bpffs/upatches/$1/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$2" --no-precheck \
			>/dev/null 2>&1 || true
	fi
}

kernel_obs_load()
{
	if "$SHIRUDO_BIN" upatch load "$1" --no-precheck --report=- \
		>"$WORK/load.log" 2>&1; then
		return 0
	fi
	cat "$WORK/load.log" >&2
	if [ -d /mnt/shirudo-out ]; then
		cp "$WORK/load.log" "/mnt/shirudo-out/$2"
	fi
	return 1
}
