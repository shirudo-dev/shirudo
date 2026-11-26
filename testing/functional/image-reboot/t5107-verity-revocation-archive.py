#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "revocation_boot_test",
    Path(__file__).with_name("t5106-verity-revocation-boot.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
revocation = boot.revocation
config = boot.config
require = config.require
NAME = "shirudo-test-basic"
UPATCH = Path(os.environ["SHIRUDO_TEST_FIXTURES_DIR"]) / (NAME + ".upatch")
PIN = Path("/run/shirudo/bpffs/upatches") / NAME
ARCHIVE = Path("/var/lib/shirudo/upatches") / (NAME + ".upatch")
TORN_SIZE = 16
REFUSAL = f"keys revoke: {NAME}.upatch names no signer"


def keepalive():
    return json.loads(config.run("keepalive", "status", "--keepalive"))


def refused_update(label, name, keys):
    """A live update with revocation records refuses and changes nothing."""
    before = revocation.snapshot(label + "-before", keys)
    result = subprocess.run(
        [config.BINARY, "image", "update", str(config.IMAGES / name)],
        capture_output=True, text=True, timeout=120)
    (config.RESULTS / (label + ".stderr")).write_text(result.stderr)
    require(result.returncode == 1,
            f"the update was not refused: {result.returncode}\n{result.stderr}")
    require(REFUSAL in result.stderr and "nothing revoked" in result.stderr,
            f"the update did not name the archive: {result.stderr}")
    require(before == revocation.snapshot(label + "-after", keys),
            "a refused revocation changed state")


def main():
    mode = sys.argv[1]
    if mode == "tear":
        require(not PIN.exists() and not ARCHIVE.exists(), "stale upatch")
        config.run("load", "upatch", "load", UPATCH, "--no-precheck")
        require(PIN.is_dir() and ARCHIVE.is_file(), "upatch not installed")
        require(keepalive()["count"] >= 1, "the keepalive counts no upatch")
        subprocess.run([*config.fault_command(), "archive-truncate", NAME],
                       check=True)
        require(ARCHIVE.stat().st_size == TORN_SIZE, "archive not cut short")
        require(PIN.is_dir(), "cutting the archive unloaded the upatch")
    elif mode == "live":
        status = json.loads(config.run("stage-status", "image", "status",
                                       "--json"))
        if status["next_boot_root_hash"] != config.root(boot.STAGED):
            config.run("stage", "image", "stage", config.IMAGES / boot.STAGED)
        refused_update("live", boot.STAGED, 2)
        status = json.loads(config.run("staged-status", "image", "status",
                                       "--json"))
        require(status["next_boot_root_hash"] == config.root(boot.STAGED),
                "the refused update removed the stage")
        require(PIN.is_dir() and ARCHIVE.stat().st_size == TORN_SIZE,
                "the refused update touched the upatch")
    elif mode == "booted":
        status = json.loads(config.run("status", "status", "--json"))
        require(status["lsm_attached"] is True, "LSM not attached")
        require(status["tpm"]["bound_in"] == "initrd",
                f"register not bound from the initrd: {status['tpm']}")
        view = revocation.snapshot("booted", 1)
        require(view["status"]["root_hash"] == config.root(boot.STAGED),
                "the staged config is not active")
        journal = boot.initrd_journal()
        for line in (f"upatch purge: {NAME}.upatch names no signer",
                     f"keys revoke: {NAME}.upatch is left for boot-restore to ignore",
                     f"boot-restore: {NAME}.upatch is not an artifact"):
            require(line in journal, f"the initrd did not log: {line}")
        require(not PIN.exists(), "the upatch of the torn archive was restored")
        require(ARCHIVE.stat().st_size == TORN_SIZE,
                "the boot changed or removed the torn archive")
        require(NAME not in [entry["name"]
                             for entry in boot.boot_init_event()["set"]],
                "the init event counts the upatch of the torn archive")
    elif mode == "reported":
        status = json.loads(config.run("status", "status", "--json"))
        measured = [cond for cond in status["conditions"]
                    if cond["type"] == "UpatchesMeasured"]
        require(len(measured) == 1 and measured[0]["status"] == "OK",
                f"status reports the torn archive: {measured}")
        require(keepalive()["count"] == 0,
                "the keepalive counts a upatch no boot restored")
    elif mode == "live-again":
        refused_update("live-again", "config-interrupted", 1)
        require(ARCHIVE.stat().st_size == TORN_SIZE,
                "the refused update touched the torn archive")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
