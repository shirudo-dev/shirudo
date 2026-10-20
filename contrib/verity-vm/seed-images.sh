#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -eu
mkdir -p /sysroot/var/lib/shirudo/images /sysroot/etc/shirudo
cp /shirudo-test-images/*.img /shirudo-test-images/*.verity \
	/shirudo-test-images/*.roothash /shirudo-test-images/*.p7s \
	/sysroot/var/lib/shirudo/images/
cp /shirudo-test-images/bootstrap.conf /sysroot/etc/shirudo/shirudo.conf
