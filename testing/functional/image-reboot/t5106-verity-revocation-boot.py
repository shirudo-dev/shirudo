#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location(
    "revocation_test",
    Path(__file__).parent.parent / "image" / "t5104-verity-revocation.py")
revocation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(revocation)
signer = revocation.signer
config = signer.config
require = config.require
NAME = revocation.NAME
PIN = revocation.PIN
ARCHIVE = revocation.ARCHIVE
STAGED = "config-revoke"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
EVENTLOG = Path("/var/lib/shirudo/eventlog")


def cert_sha256(name):
    return hashlib.sha256((signer.FIXTURES / name).read_bytes()).hexdigest()


def boot_init_event():
    events = [json.loads(line) for line in EVENTLOG.read_text().splitlines()]
    inits = [event for event in events if event["type"] == "init"]
    require(inits, "the eventlog holds no init event")
    return inits[-1]


def initrd_journal():
    return subprocess.run(
        ["journalctl", "-b", "-u", "shirudo-initrd.service", "--no-pager",
         "-o", "cat"], check=True, capture_output=True, text=True).stdout


def main():
    mode = sys.argv[1]
    if mode == "load":
        signer.check_members(signer.keyring())
        require(not PIN.exists() and not ARCHIVE.exists(),
                "stale upatch of the boot signer")
        config.run("load", "upatch", "load", revocation.UPATCH, "--no-precheck")
        require((PIN / "link").exists() and ARCHIVE.is_file(),
                "upatch not installed")
        revocation.snapshot("loaded", 2)
    elif mode == "stage":
        before = config.load("loaded")
        config.run("stage", "image", "stage", config.IMAGES / STAGED)
        staged = revocation.snapshot("staged", 2)
        require(staged["status"]["next_boot_root_hash"] == config.root(STAGED),
                "status does not name the staged config")
        require(staged["status"]["root_hash"] == before["status"]["root_hash"] and
                staged["chain"] == before["chain"] and
                staged["keys"] == before["keys"],
                "staging changed the active config, the register or the keys")
        require((PIN / "link").exists() and ARCHIVE.is_file(),
                "staging a revocation unloaded the signer's upatch")
        staged["boot_id"] = BOOT_ID.read_text()
        config.save("staged", staged)
    elif mode == "booted":
        staged = config.load("staged")
        require(BOOT_ID.read_text() != staged["boot_id"],
                "the VM did not reboot")
        status = json.loads(config.run("status", "status", "--json"))
        require(status["lsm_attached"] is True, "LSM not attached")
        require(status["tpm"]["bound_in"] == "initrd",
                f"register not bound from the initrd: {status['tpm']}")
        require(status["tpm"]["chain_matches_eventlog"] is True,
                "register does not match the eventlog")
        booted = revocation.snapshot("booted", 1)
        require(booted["status"]["root_hash"] == config.root(STAGED),
                "the staged config is not active")
        require(booted["status"]["next_boot_root_hash"] is None,
                "the stage outlived the boot that took it")
        require(booted["status"]["reset_count"] != staged["status"]["reset_count"],
                "the TPM was not reset")
        events = booted["config"]["events"]
        require(len(events) == 1 and events[0]["kind"] == 1 and
                events[0]["root_hash"] == config.root(STAGED),
                f"the boot did not record one BOOT event of the staged config: {events}")
    elif mode == "purged":
        booted = config.load("booted")
        primary = signer.certificate_description(signer.FIXTURES / "primary.der")
        require({value[4] for value in booted["keys"].values()} == {primary},
                "the boot enrolled another key than the primary")
        require(not PIN.exists(), "the revoked signer's upatch was restored")
        require(not ARCHIVE.exists(), "the revoked signer's archive remains")
        event = boot_init_event()
        require(cert_sha256("primary.der") in event["certs"] and
                cert_sha256("boot.der") not in event["certs"],
                f"wrong certificates in the init event: {event['certs']}")
        require(NAME not in [entry["name"] for entry in event["set"]],
                "the init event counts the revoked signer's upatch")
        require(f"keys revoke: {NAME} purged from the archive" in initrd_journal(),
                "the initrd did not report the purge")
    elif mode == "refused":
        before = revocation.snapshot("before-refused", 1)
        config.run("revoked-load", "upatch", "load", revocation.UPATCH,
                   "--no-precheck", success=False)
        require(not PIN.exists() and not ARCHIVE.exists(),
                "a refused load left a pin or an archive")
        require(before == revocation.snapshot("refused", 1),
                "refused load changed state")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
