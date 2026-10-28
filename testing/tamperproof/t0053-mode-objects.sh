#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")/.."
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

test_expect_success 'the PR_SET_MM fixture matches the native identity map ABI' '
	python3 - <<"PYTEST"
import ast
import ctypes
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path.cwd().parent
path = root / "testing/tamperproof/t1131-pr-set-mm-identity.py"
definition = next(node for node in ast.parse(path.read_text()).body
                  if isinstance(node, ast.ClassDef) and node.name == "ShirudoIdentity")
namespace = {"ctypes": ctypes}
exec(compile(ast.Module(body=[definition], type_ignores=[]), str(path), "exec"), namespace)
identity = namespace["ShirudoIdentity"]
fields = [name for name, field_type in identity._fields_]
source = "\n".join([
    "#include <stddef.h>",
    "#include <stdio.h>",
    "#include \"util/identity.h\"",
    "int main(void)",
    "{",
    "\tprintf(\"%zu\\n\", sizeof(struct shirudo_identity));",
    *[f"\tprintf(\"%zu\\n\", offsetof(struct shirudo_identity, {name}));" for name in fields],
    "\treturn 0;",
    "}",
])
with tempfile.TemporaryDirectory(prefix="shirudo-identity-abi-") as directory:
    binary = Path(directory) / "identity-layout"
    command = shlex.split(os.environ.get("CC", "cc"))
    command += ["-std=gnu11", "-I" + str(root), "-I" + str(root / "include"),
                "-x", "c", "-", "-o", str(binary)]
    subprocess.run(command, input=source, text=True, check=True)
    actual = [int(value) for value in subprocess.check_output([binary], text=True).split()]
expected = [ctypes.sizeof(identity)] + [getattr(identity, name).offset for name in fields]
assert actual == expected, (actual, expected)
PYTEST
'

test_done
