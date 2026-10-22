#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

H=${SHIRUDO_TEST_MODE_OBJECTS_HELPER:-./helper/test-mode-objects}
W=$(mktemp)
trap 'rm -f "$W"' EXIT HUP INT TERM

test_expect_success 'embedded admission and seal always include image enforcement' '
	"$H" >"$W" && python3 - "$W" <<"PYTEST"
import sys
from collections import defaultdict

inventory = defaultdict(lambda: defaultdict(set))
for line in open(sys.argv[1]):
    kind, selection, name = line.split()
    inventory[selection][kind].add(name)
assert set(inventory) == {"admission", "seal"}, inventory
maps = {"shirudo_bpffs_sb", "shirudo_tasks", "shirudo_tamper",
        "shirudo_devices", "shirudo_roots"}
for selection, blob in (("admission", "bpf2"), ("seal", "seal")):
    actual = inventory[selection]
    assert actual["blob"] == {blob}, actual
    assert maps <= actual["map"], actual
assert {"shirudo_lsm_bdev_setintegrity", "shirudo_lsm_bdev_free_security",
        "shirudo_lsm_file_ioctl", "shirudo_lsm_bprm_check_security"} <= inventory["admission"]["program"]
assert {"shirudo_seal_mmap_file", "shirudo_seal_file_mprotect",
        "shirudo_seal_bprm_check_security", "shirudo_seal_inode_setxattr"} <= inventory["seal"]["program"]
assert "bpf_real_data_inode" in inventory["seal"]["extern"]
PYTEST
'

test_done
