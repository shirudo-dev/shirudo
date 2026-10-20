#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu
mkdir -p /sysroot/usr/local/bin /sysroot/var/lib/shirudo/keys/trusted
cp /usr/local/bin/shirudo /sysroot/usr/local/bin/shirudo
chmod 0755 /sysroot/usr/local/bin/shirudo
cp /etc/shirudo/keys/cert.der /sysroot/var/lib/shirudo/keys/cert.der
cp /etc/shirudo/keys/trusted/* /sysroot/var/lib/shirudo/keys/trusted/
chmod 0700 /sysroot/var/lib/shirudo /sysroot/var/lib/shirudo/keys \
	/sysroot/var/lib/shirudo/keys/trusted
