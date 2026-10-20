#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
. ./integration-lib.sh
verity_required() {
	printf 'Bail out! %s\n' "$*" >&2
	exit 1
}
target_guard

mountpoint -q /run/shirudo/runtime && mountpoint -q /run/shirudo/config ||
	verity_required "dm-verity image mode is not active"
command -v python3 >/dev/null 2>&1 || verity_required "no python3"

test_expect_success 'runtime and config filesystems enforce their mount flags' '
	python3 - <<"PY"
import os
for path in ("/run/shirudo/runtime", "/run/shirudo/config"):
    flags = os.statvfs(path).f_flag
    assert flags & os.ST_RDONLY and flags & os.ST_NOSUID and flags & os.ST_NODEV, (path, flags)
    if path.endswith("/config"):
        assert flags & os.ST_NOEXEC, (path, flags)
PY
'

test_expect_success 'active DM tables reject mutations through inherited FDs, device aliases and alternate ioctl encodings' '
	python3 tamperproof/t1150-verity-devices.py devices
'

test_expect_success 'direct image mount changes and move_mount are denied in private namespaces' '
	python3 tamperproof/t1150-verity-devices.py mounts
'

test_done
