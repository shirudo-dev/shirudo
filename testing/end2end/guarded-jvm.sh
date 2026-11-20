#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/end2end/guarded-jvm.sh <jar> -- run the jar in a JVM that a user
# manager of this node starts now, with the Java agents loaded at this
# moment and no other, and print what it printed and its exit status.

set -eu

[ $# -eq 1 ] || { echo "usage: $0 <jar>" >&2; exit 2; }
JVM_USER=shirudo-e2e-guard
id -u "$JVM_USER" >/dev/null 2>&1 ||
	useradd --create-home --user-group "$JVM_USER"
uid=$(id -u "$JVM_USER")
home=/home/$JVM_USER
unit=$home/.config/systemd/user

install -o "$JVM_USER" -m 0644 "$1" "$home/guarded.jar"
install -d -o "$JVM_USER" -g "$JVM_USER" "$home/.config" \
	"$home/.config/systemd" "$unit"
cat >"$unit/guarded-jvm.service" <<'UNIT'
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'java -jar %h/guarded.jar; echo "status $$?"'
StandardOutput=truncate:%h/guarded-jvm.out
StandardError=inherit
UNIT
chown "$JVM_USER:" "$unit/guarded-jvm.service"

# A manager reads environment.d when it starts, so one that ran before
# the last sync has the agents of before it.
loginctl enable-linger "$JVM_USER"
systemctl restart "user@$uid.service"
runuser -u "$JVM_USER" -- env XDG_RUNTIME_DIR="/run/user/$uid" \
	systemctl --user start guarded-jvm.service || {
	journalctl "_UID=$uid" --no-pager | tail -n 30 >&2
	exit 1
}
cat "$home/guarded-jvm.out"
