#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

H=${SHIRUDO_TEST_MODE_OBJECTS_HELPER:-./helper/test-mode-objects}
W=$(mktemp)
trap 'rm -f "$W"' EXIT HUP INT TERM

test_expect_success 'embedded BPF selection keeps image hooks and maps out of ordinary mode' '
	"$H" >"$W" && python3 - "$W" <<"PYTEST"
import sys
from collections import defaultdict

inventory = defaultdict(lambda: defaultdict(set))
for line in open(sys.argv[1]):
    kind, selection, name = line.split()
    inventory[selection][kind].add(name)
extra = {
    "admission": {"shirudo_lsm_file_ioctl",
                  "shirudo_lsm_bdev_setintegrity",
                  "shirudo_lsm_bdev_free_security"},
    "seal": {"shirudo_seal_mmap_file", "shirudo_seal_file_mprotect"},
}
common_maps = {"shirudo_bpffs_sb", "shirudo_tasks", "shirudo_tamper"}
for kind, blob in (("admission", "bpf2"), ("seal", "seal")):
    ordinary = inventory["ordinary-" + kind]
    image = inventory["image-" + kind]
    assert ordinary["blob"] == {blob}, ordinary
    assert image["blob"] == {blob + "_verity"}, image
    assert ordinary["program"], ordinary
    assert image["program"] == ordinary["program"] | extra[kind], inventory
    assert ordinary["program"].isdisjoint(extra[kind]), ordinary
    assert common_maps <= ordinary["map"], ordinary
    image_maps = {"shirudo_devices", "shirudo_roots"}
    assert common_maps | image_maps <= image["map"], image
    assert image_maps.isdisjoint(ordinary["map"]), ordinary
    assert "bpf_real_data_inode" not in ordinary["extern"], ordinary
    if kind == "seal":
        assert "bpf_real_data_inode" in image["extern"], image
PYTEST
'

test_done
