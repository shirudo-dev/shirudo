# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import errno
import fcntl
import os
import pathlib
import platform
import stat
import struct
import sys
import tempfile

ROOTS = ("/run/shirudo/runtime", "/run/shirudo/config")
DENIED = (errno.EPERM, errno.EACCES)
libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_char_p)
libc.umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
libc.unshare.argtypes = (ctypes.c_int,)
libc.syscall.restype = ctypes.c_long


class DmIoctl(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32 * 3),
                ("data_size", ctypes.c_uint32),
                ("data_start", ctypes.c_uint32),
                ("target_count", ctypes.c_uint32),
                ("open_count", ctypes.c_int32),
                ("flags", ctypes.c_uint32),
                ("event_nr", ctypes.c_uint32),
                ("padding", ctypes.c_uint32),
                ("dev", ctypes.c_uint64),
                ("name", ctypes.c_char * 128),
                ("uuid", ctypes.c_char * 129),
                ("data", ctypes.c_char * 7)]


assert ctypes.sizeof(DmIoctl) == 312


def dm_request(fd, command, name, table=False, replacement=None, uuid=False,
               direction=3, encoded_size=312):
    buf = bytearray(4096)
    param = DmIoctl.from_buffer(buf)
    param.version[:] = (4, 0, 0)
    param.data_size = len(buf)
    param.data_start = ctypes.sizeof(DmIoctl)
    param.name = name.encode("ascii")
    if table:
        param.flags = 1 << 4
    if replacement is not None:
        payload = replacement.encode("ascii") + b"\0"
        buf[param.data_start:param.data_start + len(payload)] = payload
        if uuid:
            param.flags |= 1 << 14
    if command == 14:
        buf[param.data_start:param.data_start + 14] = struct.pack("Q", 0) + b"probe\0"
    request = (direction << 30) | (encoded_size << 16) | (0xfd << 8) | command
    fcntl.ioctl(fd, request, buf, True)
    return bytes(buf)


def mapped_device(path):
    st = os.stat(path)
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    name = pathlib.Path(f"/sys/dev/block/{dev}/dm/name").read_text().strip()
    return name, dev


def dm_guards(fd, name):
    before = dm_request(fd, 12, name, table=True)
    status = DmIoctl.from_buffer_copy(dm_request(fd, 7, name))
    identity = (bytes(status.name), bytes(status.uuid))
    for command, label in ((9, "table load"), (10, "table clear"),
                           (4, "active device removal"), (6, "resume"),
                           (14, "target message")):
        try:
            dm_request(fd, command, name)
        except OSError as exc:
            assert exc.errno in DENIED, (name, label, exc.errno)
        else:
            raise AssertionError((name, label, "mutation was allowed"))
        assert dm_request(fd, 12, name, table=True) == before, (name, label)
    for uuid, label in ((False, "device rename"), (True, "device UUID replacement")):
        replacement = f"shirudo-denied-{os.getpid()}-{'uuid' if uuid else 'name'}"
        try:
            dm_request(fd, 5, name, replacement=replacement, uuid=uuid)
        except OSError as exc:
            assert exc.errno in DENIED, (name, label, exc.errno)
        else:
            raise AssertionError((name, label, "mutation was allowed"))
        after = DmIoctl.from_buffer_copy(dm_request(fd, 7, name))
        assert (bytes(after.name), bytes(after.uuid)) == identity, (name, label)
        assert dm_request(fd, 12, name, table=True) == before, (name, label)
    assert dm_request(fd, 7, name), (name, "read-only status denied")
    for direction, encoded_size in ((0, 0), (1, 1), (2, 0x3fff)):
        assert dm_request(fd, 7, name, direction=direction, encoded_size=encoded_size)
        try:
            dm_request(fd, 10, name, direction=direction, encoded_size=encoded_size)
        except OSError as exc:
            assert exc.errno in DENIED, (name, "noncanonical table clear",
                                         direction, encoded_size, exc.errno)
        else:
            raise AssertionError((name, "noncanonical table clear was allowed",
                                  direction, encoded_size))
        assert dm_request(fd, 12, name, table=True) == before, \
            (name, "noncanonical table clear", direction, encoded_size)


def in_namespace(fn):
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if not pid:
        os.close(read_fd)
        try:
            assert libc.unshare(0x20000) == 0, ("unshare", ctypes.get_errno())
            assert libc.mount(None, b"/", None, (1 << 18) | (1 << 14), None) == 0, \
                ("recursive private propagation", ctypes.get_errno())
            for line in open("/proc/self/mountinfo", encoding="ascii"):
                fields = line.split()
                optional = fields[6:fields.index("-")]
                assert not any(item.startswith(("shared:", "master:")) for item in optional), \
                    ("namespace propagation is not isolated", line)
            fn()
        except BaseException as exc:
            os.write(write_fd, repr(exc).encode())
            os._exit(1)
        os._exit(0)
    os.close(write_fd)
    message = os.read(read_fd, 8192)
    os.close(read_fd)
    _, status = os.waitpid(pid, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, message.decode()


def mount_attempt(path, operation, destination):
    encoded = os.fsencode(path)
    if operation == "unmount":
        result = libc.umount2(encoded, 0)
    elif operation == "lazy unmount":
        result = libc.umount2(encoded, 2)
    elif operation == "remount":
        result = libc.mount(None, encoded, None, 1 << 5, None)
    elif operation == "overmount":
        result = libc.mount(b"none", encoded, b"tmpfs", 0, None)
    elif operation == "move_mount":
        syscall = {"x86_64": 429, "aarch64": 429, "riscv64": 429}[platform.machine()]
        result = libc.syscall(syscall, -100, encoded, -100,
                              os.fsencode(destination), 0)
    elif operation == "recursive shared":
        result = libc.mount(None, encoded, None, (1 << 20) | (1 << 14), None)
    else:
        raise AssertionError(operation)
    assert result == -1 and ctypes.get_errno() in DENIED, \
        (path, operation, result, ctypes.get_errno())


mode = sys.argv[1]
if mode == "devices":
    control = os.open("/dev/mapper/control", os.O_RDWR | os.O_CLOEXEC)
    try:
        for root in ROOTS:
            name, dev = mapped_device(root)
            dm_guards(control, name)
            pid = os.fork()
            if not pid:
                try:
                    dm_guards(control, name)
                except BaseException as exc:
                    print(f"inherited control FD: {exc}", file=sys.stderr)
                    os._exit(1)
                os._exit(0)
            _, status = os.waitpid(pid, 0)
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            assert mapped_device(root) == (name, dev)
    finally:
        os.close(control)
    with tempfile.TemporaryDirectory(prefix="shirudo-dm-alias-", dir="/dev") as directory:
        alias = pathlib.Path(directory) / "control"
        os.mknod(alias, stat.S_IFCHR | 0o600, os.stat("/dev/mapper/control").st_rdev)
        control = os.open(alias, os.O_RDWR | os.O_CLOEXEC)
        try:
            for root in ROOTS:
                name, dev = mapped_device(root)
                dm_guards(control, name)
                assert mapped_device(root) == (name, dev)
        finally:
            os.close(control)
elif mode == "mounts":
    with tempfile.TemporaryDirectory() as destination:
        for root in ROOTS:
            for operation in ("unmount", "lazy unmount", "remount", "overmount", "move_mount"):
                in_namespace(lambda: mount_attempt(root, operation, destination))
else:
    raise AssertionError(mode)
print(f"verity {mode} guards passed")
