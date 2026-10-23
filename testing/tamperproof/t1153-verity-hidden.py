# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import hashlib
import os
import pathlib
import platform
import subprocess
import sys
import tempfile

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_char_p)
libc.unshare.argtypes = (ctypes.c_int,)
libc.syscall.restype = ctypes.c_long
RUNTIME = "/run/shirudo/runtime"
MODE_QUERY = 0x53520001
IMAGE_MODE_ERRNO = 1002


def keyring_contents():
    syscall = {"x86_64": 250, "aarch64": 219, "riscv64": 219}[platform.machine()]
    size = libc.syscall(syscall, 11, -9, None, 0, 0)
    assert size >= 4, ("BPF keyring read prerequisite", ctypes.get_errno())
    data = ctypes.create_string_buffer(size)
    count = libc.syscall(syscall, 11, -9, data, size, 0)
    assert count == size, ("BPF keyring read", count, size, ctypes.get_errno())
    return data.raw


def snapshot():
    files = {}
    for directory in ("/var/lib/shirudo/config-update",):
        root = pathlib.Path(directory)
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                files[str(path)] = hashlib.sha256(path.read_bytes()).digest()
    mappings = {}
    for device in pathlib.Path("/sys/block").glob("dm-*"):
        mappings[device.name] = tuple((device / name).read_text().strip()
                                     for name in ("dm/name", "dm/uuid", "dev", "diskseq"))
    return files, mappings, keyring_contents()


def chroot_run(root, command, arguments):
    def enter():
        os.chroot(root)
        os.chdir("/")
        ctypes.set_errno(0)
        mode = libc.prctl(MODE_QUERY, 0, 0, 0, 0)
        if mode != -1 or ctypes.get_errno() != IMAGE_MODE_ERRNO:
            raise RuntimeError(("mode query became hidden", mode, ctypes.get_errno()))

    return subprocess.run([*command, *arguments], preexec_fn=enter,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=30, check=False)


def isolated(root, command):
    assert libc.unshare(0x00020000) == 0, ("mount namespace prerequisite", ctypes.get_errno())
    assert libc.mount(None, b"/", None, (1 << 18) | (1 << 14), None) == 0, \
        ("recursive private namespace prerequisite", ctypes.get_errno())
    for line in open("/proc/self/mountinfo", encoding="ascii"):
        fields = line.split()
        optional = fields[6:fields.index("-")]
        assert not any(item.startswith(("shared:", "master:")) for item in optional), \
            ("namespace propagation is not isolated", line)
    destination = pathlib.Path(root + RUNTIME)
    destination.mkdir(parents=True)
    assert libc.mount(RUNTIME.encode(), str(destination).encode(), None, 4096, None) == 0, \
        ("verified runtime bind prerequisite", ctypes.get_errno())
    assert not pathlib.Path(root + "/run/shirudo/bpffs").exists()
    for arguments, expected in ((["init"], b"authenticated image settings"),
                                (["status"], b"image state"),
                                (["image", "status"], b"image state")):
        result = chroot_run(root, command, arguments)
        assert result.returncode > 0, (arguments, result.returncode, result.stderr)
        assert expected in result.stderr, (arguments, result.stderr)
        assert b"pre-flight" not in result.stderr, (arguments, result.stderr)
        assert b"error while loading shared libraries" not in result.stderr, result.stderr


def main():
    binary = os.path.abspath(sys.argv[1])
    assert binary.startswith(RUNTIME + "/"), ("runtime executable required", binary)
    command = [binary]
    healthy = subprocess.run([*command, "image", "status"], capture_output=True,
                             timeout=30, check=False)
    assert healthy.returncode == 0, ("healthy image prerequisite", healthy.stderr)
    ctypes.set_errno(0)
    mode = libc.prctl(MODE_QUERY, 0, 0, 0, 0)
    assert mode == -1 and ctypes.get_errno() == IMAGE_MODE_ERRNO, \
        ("image mode query prerequisite", mode, ctypes.get_errno())
    before = snapshot()
    with tempfile.TemporaryDirectory(prefix="shirudo-hidden-") as root:
        child = os.fork()
        if not child:
            try:
                isolated(root, command)
            except BaseException:
                import traceback
                traceback.print_exc()
                os._exit(1)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0, status
    assert snapshot() == before, "hidden-bpffs attempts altered journal, keyring or mappings"


if __name__ == "__main__":
    main()
