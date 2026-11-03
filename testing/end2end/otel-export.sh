#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

otel_setup()
{
	ca=$PWD/../build/test-vm/end2end/ca.pem
	[ -s "$ca" ] || test_skip_all "no collector CA: run make -C testing end2end"
	export OTEL_EXPORTER_OTLP_CERTIFICATE="$ca"
	OTEL_OUT=/mnt/shirudo-out/end2end/otel
	mkdir -p "$OTEL_OUT"
}

otel_export()
{
	"$SHIRUDO_BIN" upatch map "$NAME" "$1" --json="$2" --otel \
		--otel-endpoint=https://10.0.2.2:14318 >/dev/null
}
