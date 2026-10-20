#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location(
    "signer_test", Path(__file__).with_name("t1155-verity-boot-signers.py"))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
config = signer.config
require = config.require
NAME = "shirudo-test-revoked-key"
UPATCH = signer.FIXTURES / (NAME + ".upatch")
PIN = Path("/run/shirudo/bpffs/upatches") / NAME
ARCHIVE = Path("/var/lib/shirudo/upatches") / (NAME + ".upatch")


def snapshot(label, expected):
    # Pin the current register at every stage, then independently check each
    # signed load/unload event against the preceding register value below.
    (config.RESULTS / "anchor.json").unlink(missing_ok=True)
    view = config.snapshot(label)
    view["keys"] = signer.keyring(expected)["keys"]
    config.save(label, view)
    return view


def extension(before, after, kind, payload):
    event = hashlib.sha256(b"shirudo-" + kind + b"\0" +
                           bytes.fromhex(payload) + NAME.encode()).digest()
    expected = hashlib.sha256(bytes.fromhex(before["chain"]) + event).hexdigest()
    require(after["chain"] == expected, "unexpected upatch NV extension")


def main():
    mode = sys.argv[1]
    if mode == "initial":
        require(UPATCH.is_file(), "missing boot-signed upatch fixture")
        signer.check_members(signer.keyring())
        require(not PIN.exists() and not ARCHIVE.exists(), "stale revoked upatch")
        snapshot("before", 2)
    elif mode == "load":
        before = config.load("before")
        info = json.loads(config.run("upatch-info", "upatch", "info", UPATCH, "--json"))
        config.save("upatch", info)
        config.run("load", "upatch", "load", UPATCH, "--no-precheck")
        require((PIN / "link").exists() and ARCHIVE.is_file(), "upatch not installed")
        after = snapshot("loaded", 2)
        require(before["config"] == after["config"], "load changed CONFIG")
        extension(before, after, b"upatch", info["payload_sha256"])
    elif mode == "revoke":
        before = config.load("loaded")
        config.run("revoke-config", "image", "update", signer.FIXTURES / "config-revoke")
        after = snapshot("revoked", 1)
        require(not PIN.exists() and not ARCHIVE.exists(), "revoked upatch remains")
        require(after["status"]["root_hash"] == config.root("config-revoke"),
                "revocation image not active")
        require(after["status"]["sequence"] == before["status"]["sequence"] + 1 and
                after["config"]["events"][:-1] == before["config"]["events"],
                "revocation did not append exactly one CONFIG event")
        expected = signer.certificate_description(signer.FIXTURES / "primary.der")
        require({value[4] for value in after["keys"].values()} == {expected},
                "revocation removed the wrong signer")
        cert_digest = hashlib.sha256((signer.FIXTURES / "boot.der").read_bytes()).digest()
        revoke = hashlib.sha256(b"shirudo-key-revoke\0" + cert_digest).digest()
        intermediate = dict(before)
        intermediate["chain"] = hashlib.sha256(bytes.fromhex(before["chain"]) + revoke).hexdigest()
        extension(intermediate, after, b"unload", config.load("upatch")["payload_sha256"])
        config.run("revoked-load", "upatch", "load", UPATCH,
                   "--no-precheck", success=False)
        repeat = snapshot("refused-load", 1)
        require(after == repeat, "refused load changed state")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
