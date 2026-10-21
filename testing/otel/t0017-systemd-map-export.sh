#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ../test-lib.sh

WORK=$(mktemp -d)
GENERATED=$WORK/shirudo-map-export.service
GENERATED_KEEPALIVE=$WORK/shirudo-keepalive.service
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'map export service runs the configured batch exporter' '
	grep -q "^After=shirudo.service$" \
		../../systemd/shirudo-map-export.service.in &&
	grep -q "^ConditionPathExists=/run/shirudo/bpffs/lsm_link$" \
		../../systemd/shirudo-map-export.service.in &&
	grep -q "^EnvironmentFile=-/etc/shirudo/map-export.env$" \
		../../systemd/shirudo-map-export.service.in &&
	grep -q "^ExecStart=@bindir@/shirudo upatch map --all$" \
		../../systemd/shirudo-map-export.service.in
'

test_expect_success 'map export timer waits five seconds between runs' '
	grep -q "^OnBootSec=5s$" ../../systemd/shirudo-map-export.timer &&
	grep -q "^OnUnitInactiveSec=5s$" \
		../../systemd/shirudo-map-export.timer &&
	grep -q "^Unit=shirudo-map-export.service$" \
		../../systemd/shirudo-map-export.timer &&
	grep -q "^WantedBy=timers.target$" \
		../../systemd/shirudo-map-export.timer
'

test_expect_success 'keepalive service exports status with TPM and system data' '
	grep -q "^After=shirudo.service$" \
		../../systemd/shirudo-keepalive.service.in &&
	grep -q "^EnvironmentFile=-/etc/shirudo/map-export.env$" \
		../../systemd/shirudo-keepalive.service.in &&
	grep -q "^ExecStart=@bindir@/shirudo status --otel --include-system$" \
		../../systemd/shirudo-keepalive.service.in
'

test_expect_success 'keepalive timer waits five seconds between runs' '
	grep -q "^OnBootSec=5s$" ../../systemd/shirudo-keepalive.timer &&
	grep -q "^OnUnitInactiveSec=5s$" \
		../../systemd/shirudo-keepalive.timer &&
	grep -q "^Unit=shirudo-keepalive.service$" \
		../../systemd/shirudo-keepalive.timer &&
	grep -q "^WantedBy=timers.target$" \
		../../systemd/shirudo-keepalive.timer
'

test_expect_success 'target install resolves and stages exporter units' '
	sed "s|@bindir@|/opt/shirudo/bin|g" \
		../../systemd/shirudo-map-export.service.in >"$GENERATED" &&
	sed "s|@bindir@|/opt/shirudo/bin|g" \
		../../systemd/shirudo-keepalive.service.in >"$GENERATED_KEEPALIVE" &&
	(
		cd ../.. &&
		make -n -f Makefile.shirudo bindir=/opt/shirudo/bin \
			DESTDIR="$WORK/target" \
			systemdunitdir=/usr/lib/systemd/system install-target \
			>"$WORK/target.plan"
	) &&
	grep -q "^ExecStart=/opt/shirudo/bin/shirudo upatch map --all$" \
		"$GENERATED" &&
	grep -q "^ExecStart=/opt/shirudo/bin/shirudo status --otel --include-system$" \
		"$GENERATED_KEEPALIVE" &&
	grep -q "systemd/shirudo-map-export.service" "$WORK/target.plan" &&
	grep -q "systemd/shirudo-map-export.timer" "$WORK/target.plan" &&
	grep -q "systemd/shirudo-keepalive.service" "$WORK/target.plan" &&
	grep -q "systemd/shirudo-keepalive.timer" "$WORK/target.plan"
'

test_expect_success 'operator install excludes exporter units' '
	(
		cd ../.. &&
		make -n -f Makefile.shirudo DESTDIR="$WORK/operator" \
			install-operator >"$WORK/operator.plan"
	) &&
	! grep -q "shirudo-map-export" "$WORK/operator.plan" &&
	! grep -q "shirudo-keepalive" "$WORK/operator.plan"
'

test_expect_success 'target package enables and removes exporter timers safely' '
	grep -q "systemctl enable shirudo-map-export.timer" \
		../../packaging/deb/builddeb.sh &&
	grep -q "systemctl --no-reload disable --now shirudo-map-export.timer" \
		../../packaging/deb/builddeb.sh &&
	grep -q "systemctl enable shirudo-keepalive.timer" \
		../../packaging/deb/builddeb.sh &&
	grep -q "systemctl --no-reload disable --now shirudo-keepalive.timer" \
		../../packaging/deb/builddeb.sh
'

test_expect_success 'the rpm target package carries exporter timer scriptlets' '
	for unit in shirudo-map-export shirudo-keepalive
	do
		grep -q "systemctl enable $unit.timer" \
			../../packaging/rpm/buildrpm.sh &&
		grep -q "systemctl --no-reload disable --now $unit.timer" \
			../../packaging/rpm/buildrpm.sh || return 1
	done
'

test_done
