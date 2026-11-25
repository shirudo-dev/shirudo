#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

cd "$(dirname "$0")"
. ./test-lib.sh

test_expect_success 'fresh full authority requires the entry and exact frozen device' '
	./helper/test-runtime-entry policy
'

test_expect_success 'runtime binding refuses overwrite and preserves freeze failures' '
	./helper/test-runtime-entry install
'

test_expect_success 'runtime entry lookup binds usr/bin tools and refuses symlinks, directories and wrong devices' '
	python3 - <<'"'"'PY'"'"'
import pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    binary = root / "usr/bin/shirudo"
    binary.parent.mkdir(parents=True)
    def check(ok, wrong=False, count=1):
        args = ["./helper/test-runtime-entry", str(root)]
        if wrong:
            args.append("wrong-device")
        result = subprocess.run(args, text=True, capture_output=True)
        assert (result.returncode == 0) == ok, result
        if ok:
            assert result.stdout.strip() == f"ret=0 inode={binary.stat().st_ino} count={count}", result
    check(False)
    binary.write_bytes(b"authenticated runtime fixture")
    binary.chmod(0o755)
    check(True)
    # A tool of usr/bin is bound beside the entry; a data file, a symlink
    # and a directory there are not.
    tool = binary.parent / "probe"
    tool.write_bytes(b"probe")
    tool.chmod(0o755)
    check(True, count=2)
    (binary.parent / "notes").write_bytes(b"data")
    (binary.parent / "link").symlink_to(tool)
    (binary.parent / "dir").mkdir()
    check(True, count=2)
    for name in ("probe", "notes", "link"):
        (binary.parent / name).unlink()
    (binary.parent / "dir").rmdir()
    check(True)
    check(False, True)
    binary.chmod(0o644)
    check(False)
    binary.unlink()
    binary.mkdir()
    check(False)
    binary.rmdir()
    other = root / "helper"
    other.write_bytes(b"helper")
    other.chmod(0o755)
    binary.symlink_to(other)
    check(False)
    binary.unlink()
    binary.parent.rmdir()
    (root / "usr").rmdir()
    (root / "usr").symlink_to(root)
    (root / "bin").mkdir()
    (root / "bin/shirudo").write_bytes(b"worker")
    (root / "bin/shirudo").chmod(0o755)
    check(False)
PY
'

test_done
