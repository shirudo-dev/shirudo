#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time


BINARY = os.environ["SHIRUDO_BIN"]
IMAGES = Path("/var/lib/shirudo/images")
CONFIG = Path("/run/shirudo/config")
RUNTIME = Path("/run/shirudo/runtime")
JOURNAL = Path("/var/lib/shirudo/config-update")
RESULTS = Path(sys.argv[2]).resolve()
NAMES = ("config-a", "config-b", "config-boot-keys", "config-revoke",
         "config-tree-stable", "config-tree-updated", "config-tree-deleted",
         "config-tree-restored", "config-otel", "config-jsonl", "config-jsonl-bad",
         "config-interrupted", "config-builtin")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(label, *arguments, success=True):
    result = subprocess.run([BINARY, *map(str, arguments)],
                            capture_output=True, text=True, timeout=120)
    (RESULTS / (label + ".stdout")).write_text(result.stdout)
    (RESULTS / (label + ".stderr")).write_text(result.stderr)
    require(result.returncode == (0 if success else 1),
            f"{arguments}: exit {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}")
    return result.stdout


def fault_command():
    return [str(RUNTIME / "usr/bin/shirudo-image-fault")]


def root(name):
    data = (IMAGES / (name + ".roothash")).read_bytes()
    require(len(data) == 64 and all(c in b"0123456789abcdef" for c in data),
            f"invalid root encoding: {name}")
    return data.decode("ascii")


def load(name):
    return json.loads((RESULTS / (name + ".json")).read_text())


def save(name, data):
    (RESULTS / (name + ".json")).write_text(json.dumps(data, indent=2))


def mount(path):
    rows = [line for line in Path("/proc/self/mountinfo").read_text().splitlines()
            if line.split()[4] == str(path)]
    require(len(rows) == 1, f"expected one mount at {path}: {rows}")
    flags = os.statvfs(path).f_flag
    expected = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV
    if path == CONFIG:
        expected |= os.ST_NOEXEC
    require(flags & expected == expected, f"unsafe mount flags: {path}")
    return rows[0]


def mapping_inventory():
    # Deferred verification cleanup can race with sysfs inventory reads.
    deadline = time.monotonic() + 5
    while True:
        try:
            mappings = sorted(
                (p.read_text().strip(),
                 (p.parent.parent / "dev").read_text().strip())
                for p in Path("/sys/class/block").glob("dm-*/dm/name"))
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.EINVAL):
                raise
            pending = str(error)
        else:
            pending = [name for name, _ in mappings
                       if name.startswith("shirudo-verify-")]
            if not pending:
                return mappings
        require(time.monotonic() < deadline,
                f"DM inventory did not settle: {pending}")
        time.sleep(0.05)


def snapshot(label):
    # Capture effects before a subsequent command can collect stale mappings.
    effects = {
        "mount": mount(CONFIG),
        "runtime_mount": mount(RUNTIME),
        "settings": (CONFIG / "etc/shirudo/shirudo.conf").read_text(),
        "journal": {p.name: p.read_bytes().hex()
                    for p in sorted(JOURNAL.iterdir()) if p.is_file()},
        "mappings": mapping_inventory(),
    }
    status = json.loads(run(label + "-status", "image", "status", "--json"))
    require(status["consistent"] and not status["pending"], status)
    require(status["pcr"] == 14, status)
    selected = next((name for name in NAMES
                     if (IMAGES / (name + ".roothash")).exists() and
                     root(name) == status["root_hash"]), None)
    require(selected is not None, f"unexpected current root: {status}")
    tenant = "tenant-config-0000" if selected == "config-otel" else selected
    require(f"map_export.tenant_id = {tenant}\n" in effects["settings"],
            "mounted settings do not match the selected root")
    nonce = secrets.token_hex(32)
    evidence = json.loads(run(label + "-evidence", "attest",
                              "--pcrs=0,9", "--nonce=" + nonce))
    save(label + "-evidence", evidence)
    require(evidence["nonce"] == nonce, "nonce mismatch")
    require(evidence["pcr_bank"] == "sha256", "wrong PCR bank")
    require(evidence["pcr_mask"] == (1 | (1 << 9) | (1 << 14)),
            "CONFIG PCR was not added to requested quote selection")
    view = evidence["config"]
    require(view["schema"] == 1, "invalid config evidence schema")
    for field in ("pcr", "reset_count", "restart_count"):
        require(view[field] == status[field], f"status/evidence mismatch: {field}")
    events = view["events"]
    require(bool(events), "missing BOOT event")
    value = bytes.fromhex(view["initial_pcr"])
    previous = None
    for index, event in enumerate(events):
        require(event["kind"] == (2 if index else 1), "bad BOOT/UPDATE order")
        if previous is not None:
            require(event["sequence"] == previous["sequence"] + 1,
                    "discontinuous history")
        require(event["root_hash"] in tuple(root(name) for name in NAMES
                if (IMAGES / (name + ".roothash")).exists()),
                "event does not describe a signed test fixture")
        digest = hashlib.sha256(b"shirudo-config-root-v1\0" +
                                struct.pack(">I", event["kind"]) +
                                bytes.fromhex(event["root_hash"])).digest()
        value = hashlib.sha256(value + digest).digest()
        previous = event
    require(previous["sequence"] == status["sequence"] and
            previous["root_hash"] == root(selected),
            "history does not end at current root")
    pcrs = {p["index"]: p["value"] for p in evidence["pcrs"]}
    require(value.hex() == pcrs[14], "replay differs from quoted PCR")
    anchor_path = RESULTS / "anchor.json"
    anchor = load("anchor") if anchor_path.exists() else {
        "ak": evidence["ak"]["name"], "chain": evidence["register"]["value"]}
    # Pin this test session; deployment enrollment is outside this fixture.
    run(label + "-verify", "attest", "verify",
        "--evidence=" + str(RESULTS / (label + "-evidence.json")),
        "--nonce=" + nonce, "--ak-name=" + anchor["ak"],
        "--expect-chain=" + anchor["chain"],
        "--expect-config-root=" + root(selected), "--expect-config-pcr=14")
    if not anchor_path.exists():
        save("anchor", anchor)
    effects.update(status=status, config=view, pcr=pcrs[14],
                   chain=evidence["register"]["value"])
    # JSON round-trip makes tuples comparable with stored snapshots.
    effects = json.loads(json.dumps(effects))
    save(label, effects)
    return effects


def changed(before, after, name):
    require(after["status"]["root_hash"] == root(name), "wrong selected root")
    require(after["status"]["sequence"] == before["status"]["sequence"] + 1,
            "activation did not add exactly one event")
    require(after["config"]["events"][:-1] == before["config"]["events"],
            "activation rewrote config history")
    event = after["config"]["events"][-1]
    digest = hashlib.sha256(b"shirudo-config-root-v1\0" +
                            struct.pack(">I", 2) + bytes.fromhex(root(name))).digest()
    expected = hashlib.sha256(bytes.fromhex(before["pcr"]) + digest).hexdigest()
    require(event["kind"] == 2 and after["pcr"] == expected,
            "wrong live UPDATE measurement")
    require(before["pcr"] != after["pcr"], "PCR did not change")
    require(before["mount"] != after["mount"], "active mount did not change")
    require(before["runtime_mount"] == after["runtime_mount"],
            "runtime mount changed")
    require(before["chain"] == after["chain"], "upatch register changed")


def main():
    mode = sys.argv[1]
    if mode == "initial":
        # Reusing a results directory starts a fresh session pin.
        (RESULTS / "anchor.json").unlink(missing_ok=True)
        require(root("config-a") != root("config-b"), "A/B fixtures are identical")
        snapshot("initial")
    elif mode in ("root-missing", "root-wrong", "root-match"):
        before = snapshot(mode + "-before")
        result = subprocess.run(fault_command() + ["config-root", mode[5:],
                                                  str(IMAGES / "config-a")],
                                capture_output=True, text=True, timeout=120)
        (RESULTS / (mode + ".stdout")).write_text(result.stdout)
        (RESULTS / (mode + ".stderr")).write_text(result.stderr)
        require(result.returncode == 0,
                f"root fixture failed: {result.returncode}: {result.stderr}")
        after = snapshot(mode + "-after")
        differences = [key for key in before if before[key] != after[key]]
        require(not differences, f"{mode} changed state: {differences}")
    elif mode == "config-keys":
        public = Path(os.environ["SHIRUDO_TEST_KEY_FIXTURES"])
        status = json.loads(run("config-keys", "status", "--json"))
        keys = status["dm_verity_keyring"]
        expected = {hashlib.sha256((public / name).read_bytes()).hexdigest()
                    for name in ("config-c.der", "config-d.der")}
        require(len(expected) == 2, "config key fixtures are not distinct")
        require({cert["sha256"] for cert in keys["certs"]} == expected,
                "runtime did not enroll both designated config certificates")
        require(keys["other_links"] == [] and keys["serial_matches"], keys)
        require(all(cert["frozen"] and cert["config"] and cert["key_serial"]
                    for cert in keys["certs"]), keys)
    elif mode == "untrusted":
        before = snapshot("untrusted-before")
        run("untrusted-update", "image", "update", IMAGES / "config-untrusted",
            success=False)
        after = snapshot("untrusted-after")
        require(before == after, "unapproved signer changed config state")
    elif mode == "builtin":
        before = snapshot("builtin-before")
        public = Path(os.environ["SHIRUDO_TEST_KEY_FIXTURES"])
        require((public / "builtin.der").read_bytes() !=
                (RUNTIME / "etc/shirudo/config-cert.der").read_bytes(),
                "built-in certificate duplicates the boot-enrolled config certificate")
        run("builtin-update", "image", "update", IMAGES / "config-builtin",
            success=False)
        after = snapshot("builtin-after")
        require(before == after, "non-designated signer changed config state")
    elif mode in ("corrupt-data", "corrupt-hash", "corrupt-root", "corrupt-signature"):
        before = snapshot(mode + "-before")
        with tempfile.TemporaryDirectory(prefix="shirudo-image-") as directory:
            prefix = Path(directory) / "image"
            for suffix in (".img", ".verity", ".roothash", ".p7s"):
                shutil.copyfile(IMAGES / ("config-b" + suffix),
                                prefix.with_suffix(suffix))
            suffix = {"corrupt-data": ".img", "corrupt-hash": ".verity",
                      "corrupt-root": ".roothash", "corrupt-signature": ".p7s"}[mode]
            with prefix.with_suffix(suffix).open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                value = stream.read(1)
                stream.seek(-1, os.SEEK_END)
                stream.write(bytes([value[0] ^ 1]))
            run(mode + "-update", "image", "update", prefix, success=False)
        after = snapshot(mode + "-after")
        differences = [key for key in before if before[key] != after[key]]
        require(not differences, f"{mode} changed state: {differences}")
    elif mode == "update":
        before = snapshot("before-a")
        if before["status"]["root_hash"] != root("config-a"):
            run("activate-a", "image", "update", IMAGES / "config-a")
            current = snapshot("a")
            changed(before, current, "config-a")
            before = current
        run("activate-b", "image", "update", IMAGES / "config-b")
        changed(before, snapshot("b"), "config-b")
    elif mode in ("malformed", "repeat"):
        before = snapshot(mode + "-before")
        require(before["status"]["root_hash"] == root("config-b"),
                "A to B test did not leave B active")
        name = "config-bad" if mode == "malformed" else "config-b"
        run(mode + "-update", "image", "update", IMAGES / name,
            success=mode == "repeat")
        after = snapshot(mode + "-after")
        differences = [key for key in before if before[key] != after[key]]
        require(not differences, f"{mode} changed state: {differences}")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
