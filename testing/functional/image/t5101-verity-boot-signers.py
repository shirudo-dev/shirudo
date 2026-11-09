#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import struct
import sys


spec = importlib.util.spec_from_file_location(
    "config_test", Path(__file__).with_name("t5102-verity-config.py"))
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
require = config.require
FIXTURES = Path(os.environ["SHIRUDO_TEST_KEY_FIXTURES"])
BOOT = FIXTURES / "config-boot-keys"
CANDIDATE = FIXTURES / "config-live-new-key"
ROOT = BOOT.with_suffix(".roothash").read_text()
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
ADD_KEY, KEYCTL = {"x86_64": (248, 250), "aarch64": (217, 219),
                   "riscv64": (217, 219)}[platform.machine()]


def syscall(number, *arguments):
    result = LIBC.syscall(ctypes.c_long(number),
                          *(ctypes.c_long(value) for value in arguments))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def describe(serial):
    buffer = ctypes.create_string_buffer(4096)
    length = syscall(KEYCTL, 6, serial, ctypes.addressof(buffer), len(buffer), 0)
    require(0 < length <= len(buffer), "key description overflow")
    fields = buffer.value.decode().split(";", 4)
    require(len(fields) == 5, "invalid key description")
    return fields


def certificate_description(path):
    # A private thread-keyring probe gets the kernel's canonical certificate ID.
    der = path.read_bytes()
    payload = ctypes.create_string_buffer(der)
    key_type = ctypes.create_string_buffer(b"asymmetric")
    serial = syscall(ADD_KEY, ctypes.addressof(key_type), 0,
                     ctypes.addressof(payload), len(der), -1)
    try:
        fields = describe(serial)
        require(fields[0] == "asymmetric", "unexpected probe key type")
        return fields[4]
    finally:
        syscall(KEYCTL, 9, serial, -1, 0, 0)


def keyring(expected=2):
    # GET_KEYRING_ID requests unpossessed SEARCH; direct READ needs no search.
    serial = -9
    identity = describe(serial)
    require(identity[0] == "keyring" and identity[4] == ".bpf", identity)
    buffer = ctypes.create_string_buffer(4096)
    length = syscall(KEYCTL, 11, serial, ctypes.addressof(buffer), len(buffer), 0)
    require(0 < length <= len(buffer) and length % 4 == 0, "bad keyring read")
    keys = {str(key): describe(key)
            for (key,) in struct.iter_unpack("=i", buffer.raw[:length])}
    require(len(keys) == expected, f"expected {expected} boot-enrolled keys: {keys}")
    require(all(value[0] == "asymmetric" for value in keys.values()), keys)
    return {"serial": serial, "identity": identity, "keys": keys}


def expect_error(expected, number, *arguments):
    try:
        syscall(number, *arguments)
    except OSError as error:
        require(error.errno == expected, f"expected errno {expected}: {error}")
    else:
        raise AssertionError(f"syscall {number} unexpectedly succeeded")


def proc_keys_serial(name):
    serials = [int(line.split()[0], 16)
               for line in Path("/proc/keys").read_text().splitlines()
               if line.split()[7:9] == ["keyring", name + ":"]]
    require(len(serials) == 1, f"expected one {name} keyring: {serials}")
    return serials[0]


def config_keyring():
    special = -10  # KEY_SPEC_DM_VERITY_KEYRING
    # GET_KEYRING_ID requests unpossessed SEARCH, which the guard denies.
    expect_error(errno.EACCES, KEYCTL, 0, special, 0, 0, 0)
    serial = proc_keys_serial(".dm-verity")
    identity = describe(special)
    require(identity[0] == "keyring" and identity[4] == ".dm-verity",
            identity)
    require(describe(serial) == identity, "special ID resolved another key")
    buffer = ctypes.create_string_buffer(4096)
    length = syscall(KEYCTL, 11, special, ctypes.addressof(buffer),
                     len(buffer), 0)
    require(0 < length <= len(buffer) and length % 4 == 0,
            "dm-verity keyring has no boot certificate")
    before = buffer.raw[:length]
    members = {key: describe(key) for (key,) in struct.iter_unpack("=i", before)}
    expected = {certificate_description(FIXTURES / name)
                for name in ("config-c.der", "config-d.der")}
    require(len(expected) == 2 and
            {fields[4] for fields in members.values()} == expected,
            f"wrong config verification keys: {members}")
    for key in members:
        expect_error(errno.EACCES, KEYCTL, 2, key, 0, 0, 0)  # REVOKE
        expect_error(errno.EACCES, KEYCTL, 21, key, 0, 0, 0)  # INVALIDATE
        expect_error(errno.EACCES, KEYCTL, 5, key, 0, 0, 0)  # SETPERM
        expect_error(errno.EACCES, KEYCTL, 9, key, special, 0, 0)  # UNLINK
    live = certificate_description(FIXTURES / "live.der")
    require(all(describe(key)[4] != live for (key,) in
                struct.iter_unpack("=i", before)),
            "test certificate already belongs to dm-verity trust")
    key_type = ctypes.create_string_buffer(b"keyring")
    name = ctypes.create_string_buffer(b".dm-verity")
    expect_error(errno.EPERM, ADD_KEY, ctypes.addressof(key_type),
                 ctypes.addressof(name), 0, 0, -1)
    # The guard denies setattr and write before the restriction is reached.
    expect_error(errno.EACCES, KEYCTL, 29, special, 0, 0, 0)
    key_type = ctypes.create_string_buffer(b"asymmetric")
    der = (FIXTURES / "live.der").read_bytes()
    payload = ctypes.create_string_buffer(der)
    expect_error(errno.EACCES, ADD_KEY, ctypes.addressof(key_type), 0,
                 ctypes.addressof(payload), len(der), special)
    require(proc_keys_serial(".dm-verity") == serial,
            "dm-verity serial changed")
    after_length = syscall(KEYCTL, 11, special, ctypes.addressof(buffer),
                           len(buffer), 0)
    require(after_length == length and buffer.raw[:length] == before,
            "dm-verity membership changed")
    config.save("dm-verity-keyring", {"serial": serial, "identity": identity,
                                     "members": before.hex()})


def check_members(ring):
    descriptions = {fields[4] for fields in ring["keys"].values()}
    expected = {certificate_description(FIXTURES / name)
                for name in ("primary.der", "boot.der")}
    require(len(expected) == 2 and descriptions == expected,
            "the live .bpf keyring does not hold exactly primary and boot keys")
    require(certificate_description(FIXTURES / "live.der") not in descriptions,
            "the new live signer was already enrolled")
    for name in ("boot", "live"):
        fingerprint = (FIXTURES / (name + ".fingerprint")).read_text().strip()
        actual = config.run(name + "-fingerprint", "bpm", "key", "fingerprint",
                            FIXTURES / (name + ".der")).strip()
        require(actual == fingerprint and len(fingerprint) == 64,
                f"wrong fixture fingerprint: {name}")
        if name == "boot":
            trusted = config.CONFIG / "keys/trusted"
            require((trusted / (fingerprint + ".der")).read_bytes() ==
                    (FIXTURES / "boot.der").read_bytes(), "wrong mounted boot key")
            require((trusted / (fingerprint + ".vouch")).stat().st_size > 0,
                    "boot signer has no vouch")


def snapshot(label):
    effects = {
        "keyring": keyring(),
        "mount": config.mount(config.CONFIG),
        "runtime_mount": config.mount(config.RUNTIME),
        "settings": (config.CONFIG / "etc/shirudo/shirudo.conf").read_text(),
        "journal": {p.name: p.read_bytes().hex()
                    for p in sorted(config.JOURNAL.iterdir()) if p.is_file()},
        "mappings": config.mapping_inventory(),
    }
    status = json.loads(config.run(label + "-status", "image", "status", "--json"))
    require(status["consistent"] and not status["pending"] and
            status["root_hash"] == ROOT and status["pcr"] == 14, status)
    require("map_export.tenant_id = config-boot-keys\n" in effects["settings"],
            "selected CONFIG does not contain the boot-key fixture settings")
    nonce = secrets.token_hex(32)
    evidence = json.loads(config.run(label + "-evidence", "attest",
                                     "--pcrs=0,9", "--nonce=" + nonce))
    config.save(label + "-evidence", evidence)
    view = evidence["config"]
    require(evidence["nonce"] == nonce and evidence["pcr_bank"] == "sha256",
            "incorrect nonce or PCR bank")
    require(evidence["pcr_mask"] == (1 | (1 << 9) | (1 << 14)),
            "CONFIG PCR missing from quote")
    require(view["schema"] == 1, "invalid CONFIG evidence schema")
    for field in ("pcr", "reset_count", "restart_count"):
        require(view[field] == status[field], f"status/evidence mismatch: {field}")
    require(len(view["events"]) == 1, "expected one BOOT event this boot")
    event = view["events"][0]
    require(event["sequence"] == status["sequence"], "BOOT sequence mismatch")
    require(event["kind"] == 1 and event["root_hash"] == ROOT,
            "BOOT did not select the signed boot-key fixture")
    digest = hashlib.sha256(b"shirudo-config-root-v1\0" +
                            struct.pack(">I", 1) + bytes.fromhex(ROOT)).digest()
    after = hashlib.sha256(bytes.fromhex(view["initial_pcr"]) + digest).hexdigest()
    pcrs = {entry["index"]: entry["value"] for entry in evidence["pcrs"]}
    require(pcrs[14] == after, "BOOT replay disagrees with quoted PCR")
    anchor_path = config.RESULTS / "anchor.json"
    anchor = config.load("anchor") if anchor_path.exists() else {
        "ak": evidence["ak"]["name"], "chain": evidence["register"]["value"]}
    config.run(label + "-verify", "attest", "verify",
               "--evidence=" + str(config.RESULTS / (label + "-evidence.json")),
               "--nonce=" + nonce, "--ak-name=" + anchor["ak"],
               "--expect-chain=" + anchor["chain"],
               "--expect-config-root=" + ROOT, "--expect-config-pcr=14")
    if not anchor_path.exists():
        config.save("anchor", anchor)
    effects.update(status=status, config=view, pcr=pcrs[14],
                   chain=evidence["register"]["value"])
    effects = json.loads(json.dumps(effects))
    config.save(label, effects)
    return effects


def main():
    require(len(ROOT) == 64, "wrong boot root size")
    mode = sys.argv[1]
    if mode == "config-keyring":
        config_keyring()
    elif mode == "initial":
        (config.RESULTS / "anchor.json").unlink(missing_ok=True)
        check_members(keyring())
        snapshot("initial")
    elif mode in ("new-signer", "repeat"):
        before = snapshot(mode + "-before")
        config.run(mode + "-update", "image", "update",
                   CANDIDATE if mode == "new-signer" else BOOT,
                   success=mode == "repeat")
        if mode == "new-signer":
            error = (config.RESULTS / (mode + "-update.stderr")).read_text()
            require("BPF signer was not enrolled at boot" in error and
                    "reboot with the new trusted key set required" in error,
                    "update failed for a reason other than boot-only enrollment")
        after = snapshot(mode + "-after")
        differences = [key for key in before if before[key] != after[key]]
        require(not differences, f"{mode} changed state: {differences}")
    else:
        raise ValueError(mode)


if __name__ == "__main__":
    main()
