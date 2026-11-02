#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9105 -- the delivery path end to end. The operator built kernel-obs into
# a package, pushed it to an OCI registry and appended it to a signed
# upatch tree, and an OpenTelemetry Collector listens (end2end/host.sh).
# The target activates the signed config that points at both, and the
# units it ships pull the tree, verify and load the package, and export
# what it observes; the TPM-signed evidence goes back to the host, which
# checks it and the collector against what it published.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

E2E=$PWD/../build/test-vm/end2end
CONFIG=/var/lib/shirudo/images/config-end2end
PIN=/run/shirudo/bpffs/upatches/kernel-obs/link_0
OUT=/mnt/shirudo-out/end2end
[ -s "$E2E/ca.pem" ] && [ -s "$E2E/nonce" ] ||
	test_skip_all "no registry and collector: run make -C testing end2end"
[ -s "$CONFIG.img" ] || test_skip_all "missing config-end2end image"
[ ! -e "$PIN" ] || test_skip_all "kernel-obs is loaded"
mkdir -p "$OUT"
W=$(mktemp -d)
python3 end2end/tcp_forward.py 127.0.0.1:15443 10.0.2.2:15443 "$W/ready" &
FORWARD=$!
trap 'kill "$FORWARD" 2>/dev/null || true; rm -rf "$W"' EXIT
i=0
until [ -e "$W/ready" ]; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || test_skip_all "the registry forwarder did not start"
	sleep 0.1
done

# Start a unit and wait for it; its journal is what a failure needs.
unit_ok() {
	systemctl start "$1" && return 0
	journalctl -u "$1" --no-pager | tail -n 30 >&2
	return 1
}

test_expect_success 'the target trusts the CA of the registry and the collector' '
	[ -s "$E2E/ca.pem" ] &&
	[ ! -e "$E2E/ca.key" ] &&
	[ ! -e "$E2E/server.key" ] &&
	[ ! -e "$E2E/signing_key.pem" ] &&
	install -m 0644 "$E2E/ca.pem" /etc/shirudo/end2end-ca.pem &&
	install -d /etc/shirudo/bpm &&
	printf "BPM_OCI_CA_FILE=/etc/shirudo/end2end-ca.pem\n" \
		>/etc/shirudo/bpm/environment &&
	printf "OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/end2end-ca.pem\n" \
		>/etc/shirudo/map-export.env
'

test_expect_success 'the signed end2end config activates live' '
	"$SHIRUDO_BIN" image update "$CONFIG" >"$OUT/image-update.out" 2>&1 &&
	"$SHIRUDO_BIN" image status >"$OUT/image-status.out" 2>&1
'

test_expect_success 'the tree sync unit pulls, verifies and loads the package' '
	unit_ok shirudo-bpm-tree-sync.service &&
	[ -e "$PIN" ] &&
	"$SHIRUDO_BIN" status --json >"$OUT/status.json"
'

test_expect_success 'the map export unit ships what the package observed' '
	python3 end2end/kernel_obs_events.py exec &&
	unit_ok shirudo-map-export.service
'

test_expect_success 'the target attests what it runs' '
	"$SHIRUDO_BIN" attest --nonce="$(cat "$E2E/nonce")" \
		--out="$OUT/evidence.json" &&
	[ -s "$OUT/evidence.json" ]
'

test_done
