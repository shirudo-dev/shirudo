#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "config_test", Path(__file__).with_name("t1154-verity-config.py"))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


def main():
    mode = sys.argv[1]
    commands = {
        "enrollment": [("keys", "add", "missing.der", "--vouch", "missing.vouch"),
                       ("bpm", "key", "add", "oci://example.invalid/package:latest")],
        "mutation": [("keys", "revoke", "a" * 64),
                     ("bpm", "config", "register", "add", "new",
                      "oci://example.invalid", "--key-file", "missing.der"),
                     ("bpm", "config", "register", "remove", "new"),
                     ("bpm", "config", "register", "rm", "new")],
        "help": [("keys", "add", "--help"), ("keys", "revoke", "--help"),
                 ("bpm", "key", "add", "--help")],
    }
    before = config.snapshot(mode + "-before")
    for index, arguments in enumerate(commands[mode]):
        label = mode + str(index)
        config.run(label, *arguments, success=mode == "help")
        if mode != "help":
            error = (config.RESULTS / (label + ".stderr")).read_text()
            config.require("image mode:" in error and "signed" in error,
                           "missing image-mode guidance: " + error)
            wanted = "reboot" if mode == "enrollment" else "shirudo image update"
            config.require(wanted in error, "missing recovery action: " + error)
    after = config.snapshot(mode + "-after")
    config.require(before == after, "CLI refusal/help changed measured state")


if __name__ == "__main__":
    main()
