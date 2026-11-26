#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/../.."
. ./test-lib.sh

WORK=$(mktemp -d)
GENERATED_BPM=$WORK/shirudo-bpm-repo-update.service
trap 'rm -rf "$WORK"' EXIT

test_expect_success 'BPM repository refresh service runs update before upgrade' '
	grep -q "^Wants=network-online.target$" \
		../systemd/shirudo-bpm-repo-update.service.in &&
	grep -q "^After=network-online.target shirudo.service$" \
		../systemd/shirudo-bpm-repo-update.service.in &&
	grep -q "^RequiresMountsFor=/etc/shirudo/bpm /var/lib/shirudo$" \
		../systemd/shirudo-bpm-repo-update.service.in &&
	grep -q "^ConditionPathIsMountPoint=/run/shirudo/runtime$" \
		../systemd/shirudo-bpm-repo-update.service.in &&
	grep -q "^EnvironmentFile=-/etc/shirudo/bpm/environment$" \
		../systemd/shirudo-bpm-repo-update.service.in &&
	grep -n "bpm repo update" \
		../systemd/shirudo-bpm-repo-update.service.in |
		cut -d: -f1 >"$WORK/bpm-update-line" &&
	grep -n "bpm upgrade" \
		../systemd/shirudo-bpm-repo-update.service.in |
		cut -d: -f1 >"$WORK/bpm-upgrade-line" &&
	test "$(cat "$WORK/bpm-update-line")" -lt \
		"$(cat "$WORK/bpm-upgrade-line")"
'

test_expect_success 'the BPM services have a start timeout' '
	for u in bpm-repo-update bpm-tree-sync; do
		grep -q "^TimeoutStartSec=" ../systemd/shirudo-$u.service.in ||
			return 1
	done
'

test_expect_success 'BPM repository refresh timer runs at boot and every minute' '
	grep -q "^OnBootSec=0s$" \
		../systemd/shirudo-bpm-repo-update.timer &&
	grep -q "^OnUnitInactiveSec=60s$" \
		../systemd/shirudo-bpm-repo-update.timer &&
	grep -q "^AccuracySec=1s$" \
		../systemd/shirudo-bpm-repo-update.timer &&
	grep -q "^Unit=shirudo-bpm-repo-update.service$" \
		../systemd/shirudo-bpm-repo-update.timer &&
	grep -q "^WantedBy=timers.target$" \
		../systemd/shirudo-bpm-repo-update.timer
'

test_expect_success 'target install stages BPM refresh units using the runtime image' '
	sed "s|@bindir@|/opt/shirudo/bin|g" \
		../systemd/shirudo-bpm-repo-update.service.in >"$GENERATED_BPM" &&
	(
		cd .. &&
		make -n -f Makefile.shirudo bindir=/opt/shirudo/bin \
			DESTDIR="$WORK/target" \
			systemdunitdir=/usr/lib/systemd/system install-target \
			>"$WORK/target.plan"
	) &&
	grep -q "^ExecStart=-/run/shirudo/runtime/usr/bin/shirudo bpm repo update$" \
		"$GENERATED_BPM" &&
	grep -q "^ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm upgrade$" \
		"$GENERATED_BPM" &&
	grep -q "^ExecStart=/run/shirudo/runtime/usr/bin/shirudo bpm tree sync$" \
		../systemd/shirudo-bpm-tree-sync.service.in &&
	grep -q "^ConditionPathIsMountPoint=/run/shirudo/runtime$" \
		../systemd/shirudo-bpm-tree-sync.service.in &&
	grep -q "systemd/shirudo.service" "$WORK/target.plan" &&
	grep -q "systemd/shirudo-bpm-repo-update.service" "$WORK/target.plan" &&
	grep -q "systemd/shirudo-bpm-repo-update.timer" "$WORK/target.plan"
'

test_expect_success 'operator install excludes the BPM refresh unit' '
	(
		cd .. &&
		make -n -f Makefile.shirudo DESTDIR="$WORK/operator" \
			install-operator >"$WORK/operator.plan"
	) &&
	! grep -q "shirudo-bpm-repo-update" "$WORK/operator.plan"
'

test_expect_success 'target package enables and removes the BPM refresh timer' '
	grep -q "systemctl enable shirudo-bpm-repo-update.timer" \
		../packaging/deb/builddeb.sh &&
	grep -q "systemctl --no-reload disable --now shirudo-bpm-repo-update.timer" \
		../packaging/deb/builddeb.sh
'

test_expect_success 'the rpm target package carries BPM and service timer scriptlets' '
	for unit in shirudo-bpm-repo-update shirudo-bpm-tree-sync
	do
		grep -q "systemctl enable $unit.timer" ../packaging/rpm/buildrpm.sh &&
		grep -q "systemctl --no-reload disable --now $unit.timer" \
			../packaging/rpm/buildrpm.sh || return 1
	done &&
	grep -q "systemctl enable shirudo.service" ../packaging/rpm/buildrpm.sh &&
	grep -q "systemctl --no-reload disable shirudo.service" \
		../packaging/rpm/buildrpm.sh
'

test_done
