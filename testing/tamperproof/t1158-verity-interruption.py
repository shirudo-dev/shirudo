#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "config_test", Path(__file__).with_name("t1154-verity-config.py"))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
RESULTS = config.RESULTS


def fault_command():
    runtime = config.RUNTIME
    directories = []
    for directory, _, files in os.walk(runtime, followlinks=False):
        if any(name.endswith(".so") or ".so." in name for name in files):
            directories.append(directory)
    library_path = ":".join(sorted(directories))
    for name in ("lib64/ld-linux-x86-64.so.2", "lib/ld-linux-aarch64.so.1",
                 "lib/ld-linux-riscv64-lp64d.so.1"):
        interpreter = runtime / name
        if interpreter.is_file():
            return [str(interpreter), "--inhibit-cache", "--library-path",
                    library_path, str(runtime / "usr/bin/shirudo-image-fault")]
    raise AssertionError("runtime ELF interpreter missing")


def pcr(label):
    result = subprocess.run(["tpm2_pcrread", "sha256:14"], capture_output=True,
                            text=True, timeout=30)
    (RESULTS / (label + ".pcr.stdout")).write_text(result.stdout)
    (RESULTS / (label + ".pcr.stderr")).write_text(result.stderr)
    config.require(result.returncode == 0, f"PCR read failed: {result.stderr}")
    match = re.search(r"14\s*:\s*0x([0-9a-fA-F]{64})", result.stdout)
    config.require(match is not None, f"missing SHA-256 PCR 14: {result.stdout}")
    return match.group(1).lower()


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "anchor.json").unlink(missing_ok=True)
    before = config.snapshot("before")
    target = "config-interrupted"
    config.require(before["status"]["root_hash"] != config.root(target),
                   "interruption fixture was already active")
    config.require(pcr("before") == before["pcr"], "quote/PCR mismatch before crash")
    digest = hashlib.sha256(b"shirudo-config-root-v1\0" + struct.pack(">I", 2) +
                            bytes.fromhex(config.root(target))).digest()
    expected = hashlib.sha256(bytes.fromhex(before["pcr"]) + digest).hexdigest()
    result = subprocess.run(fault_command() + ["image", "update",
                                              str(config.IMAGES / target)],
                            capture_output=True, text=True, timeout=120)
    (RESULTS / "crash.stdout").write_text(result.stdout)
    (RESULTS / "crash.stderr").write_text(result.stderr)
    config.require(result.returncode == 99,
                   f"fault did not fire: exit {result.returncode}: {result.stderr}")
    (RESULTS / "crash.state").write_bytes((config.JOURNAL / "state").read_bytes())
    (RESULTS / "crash.events").write_bytes((config.JOURNAL / "events").read_bytes())
    config.require(pcr("crash") == expected, "config PCR did not extend exactly once")
    status = json.loads(config.run("pending-status", "image", "status", success=False))
    config.require(status["pending"] and not status["consistent"],
                   "interrupted activation looked healthy")
    config.run("blocked-update", "image", "update", config.IMAGES / target, success=False)
    config.run("blocked-init", "init", success=False)
    config.run("blocked-attest", "attest", "--nonce=" + "a5" * 32, success=False)
    config.require(pcr("after-refusals") == expected, "refusal retried PCR extension")


if __name__ == "__main__":
    main()
