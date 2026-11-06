#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import subprocess

spec = importlib.util.spec_from_file_location(
    "signer_test", Path(__file__).with_name("t5101-verity-boot-signers.py"))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
config = signer.config
require = config.require
NAME = "shirudo-test-revoked-key"
UPATCH = signer.FIXTURES / (NAME + ".upatch")
PIN = Path("/run/shirudo/bpffs/upatches") / NAME
ARCHIVE = Path("/var/lib/shirudo/upatches") / (NAME + ".upatch")
XDP_NAME = "shirudo-test-revoked-xdp"
XDP_UPATCH = signer.FIXTURES / (XDP_NAME + ".upatch")
XDP_PIN = PIN.parent / XDP_NAME
XDP_ARCHIVE = ARCHIVE.parent / (XDP_NAME + ".upatch")


def snapshot(label, expected):
    # Pin the current register at every stage, then independently check each
    # signed load/unload event against the preceding register value below.
    (config.RESULTS / "anchor.json").unlink(missing_ok=True)
    view = config.snapshot(label)
    view["keys"] = signer.keyring(expected)["keys"]
    config.save(label, view)
    return view


def extension(before, after, kind, payload, name=NAME):
    event = hashlib.sha256(b"shirudo-" + kind + b"\0" +
                           bytes.fromhex(payload) + name.encode()).digest()
    expected = hashlib.sha256(bytes.fromhex(before["chain"]) + event).hexdigest()
    require(after["chain"] == expected, "unexpected upatch NV extension")


def revocation_extensions(before, after):
    lines = Path("/var/lib/shirudo/eventlog").read_text().splitlines()
    events = [json.loads(line) for line in lines[before["nv_events"]:]]
    require(events and events[0]["type"] == "key_revoke",
            f"revocation is not the first new NV event: {events}")
    cert_digest = hashlib.sha256((signer.FIXTURES / "boot.der").read_bytes()).digest()
    expected_revoke = hashlib.sha256(
        b"shirudo-key-revoke\0" + cert_digest).digest()
    require(events[0]["digest"] == expected_revoke.hex(),
            "wrong signer revocation event")
    chain = bytes.fromhex(before["chain"])
    unloaded = set()
    for event in events:
        if event["type"] == "key_revoke":
            digest = bytes.fromhex(event["digest"])
        else:
            require(event["type"] == "upatch_unload",
                    f"unexpected event during signer revocation: {event}")
            patch = event["upatch"]
            name = patch["name"]
            digest = hashlib.sha256(
                b"shirudo-unload\0" + bytes.fromhex(patch["payload_sha256"]) +
                name.encode()).digest()
            require(event["digest"] == digest.hex(),
                    f"wrong unload event digest: {event}")
            unloaded.add(name)
        chain = hashlib.sha256(chain + digest).digest()
    require({NAME, XDP_NAME} <= unloaded,
            "revoked signer upatches have no measured unload")
    require(after["chain"] == chain.hex(),
            f"NV chain does not replay added revocation events: {events}")


def main():
    mode = sys.argv[1]
    if mode == "initial":
        require(UPATCH.is_file(), "missing boot-signed upatch fixture")
        require(XDP_UPATCH.is_file(), "missing boot-signed XDP fixture")
        signer.check_members(signer.keyring())
        require(not PIN.exists() and not ARCHIVE.exists(), "stale revoked upatch")
        require(not XDP_PIN.exists() and not XDP_ARCHIVE.exists(),
                "stale revoked XDP upatch")
        before = snapshot("before", 2)
        before["nv_events"] = len(
            Path("/var/lib/shirudo/eventlog").read_text().splitlines())
        config.save("before", before)
    elif mode == "load":
        before = config.load("before")
        info = json.loads(config.run("upatch-info", "upatch", "info", UPATCH, "--json"))
        config.save("upatch", info)
        config.run("load", "upatch", "load", UPATCH, "--no-precheck")
        require((PIN / "link").exists() and ARCHIVE.is_file(), "upatch not installed")
        after = snapshot("loaded", 2)
        require(before["config"] == after["config"], "load changed CONFIG")
        extension(before, after, b"upatch", info["payload_sha256"])
        subprocess.run(["ip", "link", "add", "xdprev0", "type", "veth",
                        "peer", "name", "xdprev1"], check=True)
        for device in ("xdprev0", "xdprev1"):
            subprocess.run(["ip", "link", "set", device, "up"], check=True)
        xdp_info = json.loads(config.run("xdp-info", "upatch", "info",
                                         XDP_UPATCH, "--json"))
        config.run("xdp-load", "upatch", "load", XDP_UPATCH, "--no-precheck")
        require((XDP_PIN / "link_0").exists() and XDP_ARCHIVE.is_file(),
                "XDP upatch not installed")
        attached = []
        for device in ("xdprev0", "xdprev1"):
            query = subprocess.run(["helper/test-xdp", "query", device],
                                   check=True, capture_output=True, text=True)
            attached.append(int(query.stdout.strip()))
        require(sum(bool(value) for value in attached) == 1,
                "XDP must attach to exactly one veth endpoint")
        xdp_after = snapshot("xdp-loaded", 2)
        extension(after, xdp_after, b"upatch", xdp_info["payload_sha256"], XDP_NAME)
        after = xdp_after
        after["nv_events"] = len(
            Path("/var/lib/shirudo/eventlog").read_text().splitlines())
        config.save("loaded", after)
    elif mode == "revoke":
        before = config.load("loaded")
        config.run("revoke-config", "image", "update", signer.FIXTURES / "config-revoke")
        after = snapshot("revoked", 1)
        require(not PIN.exists() and not ARCHIVE.exists(), "revoked upatch remains")
        require(not XDP_PIN.exists() and not XDP_ARCHIVE.exists(),
                "revoked XDP upatch remains")
        for device in ("xdprev0", "xdprev1"):
            query = subprocess.run(["helper/test-xdp", "query", device],
                                   check=True, capture_output=True, text=True)
            require(query.stdout.strip() == "0", "revoked XDP is still attached")
        subprocess.run(["ip", "link", "del", "xdprev0"], check=True)
        require(after["status"]["root_hash"] == config.root("config-revoke"),
                "revocation image not active")
        require(after["status"]["sequence"] == before["status"]["sequence"] + 1 and
                after["config"]["events"][:-1] == before["config"]["events"],
                "revocation did not append exactly one CONFIG event")
        expected = signer.certificate_description(signer.FIXTURES / "primary.der")
        require({value[4] for value in after["keys"].values()} == {expected},
                "revocation removed the wrong signer")
        revocation_extensions(before, after)
        config.run("revoked-load", "upatch", "load", UPATCH,
                   "--no-precheck", success=False)
        repeat = snapshot("refused-load", 1)
        require(after == repeat, "refused load changed state")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
