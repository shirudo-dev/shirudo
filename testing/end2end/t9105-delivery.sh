#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t9105 -- the delivery path end to end. The operator VM built kernel-obs
# into a package, pushed it to an OCI registry and appended it to a signed
# upatch tree, then did the same with the Java agent e2e-java it compiled
# and with the precise CVE-2026-31431 kernel-bugfix upatch, and an
# OpenTelemetry Collector listens (end2end/host.sh). The target activates
# the signed config that points at them, and the units it ships pull the
# tree, verify and load every package, and export what it observes; a JVM
# a user manager starts picks up the agent from the sealed jar; the
# shipped CVE reproducer, which reached the zero-copy splice into an
# AF_ALG socket before the sync, is refused once the delivered mitigation
# is loaded; the TPM-signed evidence goes back to the operator, which
# checks it against what it published.

cd "$(dirname "$0")/.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

E2E=$PWD/../build/test-vm/end2end
CONFIG=/var/lib/shirudo/images/config-end2end
PIN=/run/shirudo/bpffs/upatches/kernel-obs/link_0
CVE=cve-2026-31431-alg-splice-block
PIN_CVE=/run/shirudo/bpffs/upatches/$CVE/link
PROBE=${SHIRUDO_TEST_FIXTURES_DIR:-}/cve-2026-31431-splice-probe.py
OUT=/mnt/shirudo-out/end2end
JAR=/run/shirudo-java/e2e-java.jar
JAVA_USER=shirudo-e2e-java
[ -s "$E2E/ca.pem" ] && [ -s "$E2E/nonce" ] ||
	test_skip_all "no registry and collector: run make -C testing end2end"
[ -s "$CONFIG.img" ] || test_skip_all "missing config-end2end image"
[ ! -e "$PIN" ] || test_skip_all "kernel-obs is loaded"
[ ! -e "$PIN_CVE" ] || test_skip_all "the CVE mitigation is loaded"
mkdir -p "$OUT"

# The shipped probe reaches the zero-copy splice into an AF_ALG socket
# (SPLICE_OK) until the delivered mitigation refuses it (SPLICE_BLOCKED);
# UNSUPPORTED is a kernel with no AF_ALG aead interface to exercise. It is
# read before the sync, while no mitigation is loaded.
BEFORE=UNSUPPORTED
if [ -s "$PROBE" ]; then
	BEFORE=$(python3 "$PROBE" 2>/dev/null </dev/null)
fi
# The tree names the registry as the operator pushed to it, at QEMU's
# address for the host.
sed -E -i '/^[^#]*[[:space:]]registry\.test([[:space:]]|$)/d' /etc/hosts
printf '10.0.2.2 registry.test\n' >>/etc/hosts

# The JVM's user and its manager, which lingering keeps up, go with the
# test; the agent stays loaded for the evidence.
cleanup() {
	uid=$(id -u "$JAVA_USER" 2>/dev/null) || return 0
	loginctl disable-linger "$JAVA_USER" 2>/dev/null || true
	systemctl stop "user@$uid.service" 2>/dev/null || true
	userdel -r "$JAVA_USER" 2>/dev/null || true
}
trap cleanup EXIT

# A command of the JVM's user against its manager, over the manager's
# private socket, which needs no session bus.
as_java_user() {
	runuser -u "$JAVA_USER" -- \
		env XDG_RUNTIME_DIR="/run/user/$(id -u "$JAVA_USER")" "$@"
}

# The JVM, as a service of the user's manager, which gives it the
# manager's environment.
java_unit() {
	dir=/home/$JAVA_USER/.config/systemd/user
	install -d -o "$JAVA_USER" -g "$JAVA_USER" \
		"/home/$JAVA_USER/.config" "/home/$JAVA_USER/.config/systemd" "$dir" &&
	cat >"$dir/shirudo-e2e-java.service" <<-'EOF' &&
	[Service]
	Type=oneshot
	ExecStart=java -version
	StandardOutput=truncate:%h/java-version.out
	StandardError=inherit
	EOF
	chown "$JAVA_USER:" "$dir/shirudo-e2e-java.service"
}

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

test_expect_success 'the same sync delivered and pinned the CVE mitigation' '
	[ -e "$PIN_CVE" ]
'

# The effect is exercised only where the kernel offers the AF_ALG aead
# path; the delivery above holds either way. SPLICE_OK before the sync
# proves the probe reached the splice the mitigation now refuses.
if [ "$BEFORE" = SPLICE_OK ]; then
	test_expect_success 'the delivered mitigation blocks the zero-copy splice' '
		[ "$(python3 "$PROBE" 2>/dev/null </dev/null)" = SPLICE_BLOCKED ]
	'
fi

test_expect_success 'the sync installs the Java agent and names it in JAVA_TOOL_OPTIONS' '
	[ "$(stat -c %a "$JAR")" = 644 ] &&
	grep -qxF "JAVA_TOOL_OPTIONS=\"\${JAVA_TOOL_OPTIONS:+\$JAVA_TOOL_OPTIONS }-javaagent:$JAR\"" \
		/run/environment.d/shirudo.conf
'

# environment.d reaches JVMs through a user manager, which reads it when
# it starts: this one starts after the sync.
test_expect_success 'a JVM a user manager starts loads the agent from the sealed jar' '
	useradd --create-home --user-group "$JAVA_USER" &&
	loginctl enable-linger "$JAVA_USER" &&
	systemctl start "user@$(id -u "$JAVA_USER").service" &&
	as_java_user systemctl --user show-environment \
		>"$OUT/java-user-environment" &&
	grep -qx "JAVA_TOOL_OPTIONS=-javaagent:$JAR" "$OUT/java-user-environment" &&
	java_unit &&
	as_java_user systemctl --user daemon-reload &&
	as_java_user systemctl --user start shirudo-e2e-java.service &&
	cp "/home/$JAVA_USER/java-version.out" "$OUT/java-version.out" &&
	grep -qx "Picked up JAVA_TOOL_OPTIONS: -javaagent:$JAR" \
		"$OUT/java-version.out" &&
	grep -qx "shirudo-e2e-agent: premain from $JAR" "$OUT/java-version.out"
'

test_expect_success 'the map export unit ships what the package observed' '
	python3 end2end/kernel_obs_events.py exec &&
	unit_ok shirudo-map-export.service
'

test_expect_success 'the target attests what it runs' '
	"$SHIRUDO_BIN" attest --nonce="$(cat "$E2E/nonce")" \
		--output="$OUT/evidence.json" &&
	[ -s "$OUT/evidence.json" ]
'

test_done
