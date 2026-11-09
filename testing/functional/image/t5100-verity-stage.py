#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import importlib.util
from pathlib import Path
import subprocess


spec = importlib.util.spec_from_file_location(
    "boot_signers", Path(__file__).with_name("t5101-verity-boot-signers.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)
config = boot.config
require = config.require
candidate = config.IMAGES / "config-live-new-key"


def active(snapshot):
    snapshot["journal"].pop("next-boot", None)
    snapshot["status"].pop("next_boot_root_hash", None)
    return snapshot


before = config.snapshot("stage-before")
keys_before = boot.keyring()
require(before["status"]["next_boot_root_hash"] is None,
        "test started with an existing staged selection")
config.run("stage-live-refused", "image", "update", candidate, success=False)
require(before == config.snapshot("stage-live-refused-after"),
        "refusing live signer enrollment changed the current selection")
config.run("stage", "image", "stage", candidate)
staged = config.snapshot("stage-after")
require(staged["status"]["next_boot_root_hash"] == config.root(candidate.name),
        "status does not name the staged config")
require("next-boot" in staged["journal"], "staged selection is not durable")
require(active(staged) == active(before),
        "staging changed a live mount, key set, measurement or config history")
require(boot.keyring() == keys_before, "staging enrolled a key during this boot")
result = subprocess.run([config.BINARY, "init"], capture_output=True, text=True,
                        timeout=120)
(config.RESULTS / "stage-init.stdout").write_text(result.stdout)
(config.RESULTS / "stage-init.stderr").write_text(result.stderr)
require(result.returncode in (0, 1), f"unexpected init result: {result}")
after_init = config.snapshot("stage-init-after")
require(after_init["status"]["next_boot_root_hash"] == config.root(candidate.name),
        "same-boot init consumed the staged config")
require(active(after_init) == active(before),
        "same-boot init activated or measured the staged config")
require(boot.keyring() == keys_before, "same-boot init enrolled the staged signer")
config.run("stage-cancel", "image", "stage", "--cancel")
config.run("stage-cancel-again", "image", "stage", "--cancel")
after_cancel = config.snapshot("stage-cancel-after")
require(after_cancel["status"]["next_boot_root_hash"] is None,
        "cancel did not remove the staged config")
require(active(after_cancel) == active(before),
        "canceling changed a live mount, key set or measurement")
require(boot.keyring() == keys_before, "canceling changed the BPF key set")
