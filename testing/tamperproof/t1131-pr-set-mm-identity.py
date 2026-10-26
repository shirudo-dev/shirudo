# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import errno
import os
import platform
import sys

PR_SET_MM = 35
PR_SET_MM_EXE_FILE = 13
PR_SET_MM_MAP = 14
SHIRUDO_COMMAND = os.path.abspath(sys.argv[1])
RUNTIME = "/run/shirudo/runtime"

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                       ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long

ctypes.set_errno(0)
result = libc.prctl(0x53520001, 0, 0, 0, 0)
assert result == -1 and ctypes.get_errno() == 1002, "enforcement missing"
SHIRUDO = os.path.abspath(os.environ.get("SHIRUDO_TEST_RUNTIME_BIN",
                                        RUNTIME + "/usr/bin/shirudo"))
SHIRUDO_ID = os.stat(SHIRUDO).st_dev, os.stat(SHIRUDO).st_ino
OTHER = next(os.path.realpath(path) for path in
             ("/bin/true", "/usr/bin/true", sys.executable)
             if os.path.isfile(path) and os.access(path, os.X_OK) and
             (os.stat(path).st_dev, os.stat(path).st_ino) != SHIRUDO_ID)

BPF_SYSCALL = {"x86_64": 321, "aarch64": 280,
               "riscv64": 280}[platform.machine()]
BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_LOOKUP_ELEM = 1
BPF_F_RDONLY = 1 << 3


class ObjGetAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64),
                ("bpf_fd", ctypes.c_uint32),
                ("file_flags", ctypes.c_uint32)]


class MapElemAttr(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32),
                ("pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64),
                ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class ObjInfoAttr(ctypes.Structure):
    _fields_ = [("bpf_fd", ctypes.c_uint32),
                ("info_len", ctypes.c_uint32),
                ("info", ctypes.c_uint64)]


class MapInfoPrefix(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("key_size", ctypes.c_uint32),
                ("value_size", ctypes.c_uint32),
                ("max_entries", ctypes.c_uint32),
                ("map_flags", ctypes.c_uint32)]


class ShirudoIdentity(ctypes.Structure):
    _fields_ = [("sb_dev", ctypes.c_uint32),
                ("run_dev", ctypes.c_uint32),
                ("keyring_serial", ctypes.c_int32),
                ("keyring_type", ctypes.c_uint32),
                ("n_keys", ctypes.c_uint32),
                ("key_serials", ctypes.c_int32 * 16),
                ("runtime_root", ctypes.c_uint8 * 32),
                ("nv_writer_ring", ctypes.c_int32),
                ("nv_writer_key", ctypes.c_int32),
                ("nv_writer_public", ctypes.c_uint8 * 384)]


def assert_frozen_runtime():
    path = b"/run/shirudo/bpffs/identity\0"
    name = ctypes.create_string_buffer(path)
    get_attr = ObjGetAttr(ctypes.addressof(name), 0, BPF_F_RDONLY)
    fd = libc.syscall(BPF_SYSCALL, BPF_OBJ_GET, ctypes.byref(get_attr),
                      ctypes.sizeof(get_attr))
    assert fd >= 0, ("open identity map", ctypes.get_errno())
    try:
        info = MapInfoPrefix()
        info_attr = ObjInfoAttr(fd, ctypes.sizeof(info), ctypes.addressof(info))
        result = libc.syscall(BPF_SYSCALL, BPF_OBJ_GET_INFO_BY_FD,
                              ctypes.byref(info_attr), ctypes.sizeof(info_attr))
        assert result == 0, ("identity map metadata", ctypes.get_errno())
        assert info.type == 2 and info.key_size == 4 and info.max_entries == 1, \
            ("identity map shape", info.type, info.key_size, info.max_entries)
        assert ctypes.sizeof(ShirudoIdentity) <= info.value_size <= 1024 * 1024, \
            ("identity map value size", info.value_size)
        key = ctypes.c_uint32(0)
        buffer = ctypes.create_string_buffer(info.value_size)
        lookup_attr = MapElemAttr(fd, 0, ctypes.addressof(key),
                                  ctypes.addressof(buffer), 0)
        result = libc.syscall(BPF_SYSCALL, BPF_MAP_LOOKUP_ELEM,
                              ctypes.byref(lookup_attr),
                              ctypes.sizeof(lookup_attr))
        assert result == 0, ("read identity map", ctypes.get_errno())
    finally:
        os.close(fd)
    value = ShirudoIdentity.from_buffer_copy(buffer.raw)
    assert info.value_size == ctypes.sizeof(ShirudoIdentity), info.value_size
    assert any(value.runtime_root), "runtime hash missing"
    executable = os.path.realpath(SHIRUDO)
    runtime = os.path.realpath(RUNTIME)
    assert os.path.commonpath((executable, runtime)) == runtime, executable
    assert os.stat(executable).st_dev == os.stat(runtime).st_dev, executable


class PrctlMmMap(ctypes.Structure):
    _fields_ = [("start_code", ctypes.c_uint64),
                ("end_code", ctypes.c_uint64),
                ("start_data", ctypes.c_uint64),
                ("end_data", ctypes.c_uint64),
                ("start_brk", ctypes.c_uint64),
                ("brk", ctypes.c_uint64),
                ("start_stack", ctypes.c_uint64),
                ("arg_start", ctypes.c_uint64),
                ("arg_end", ctypes.c_uint64),
                ("env_start", ctypes.c_uint64),
                ("env_end", ctypes.c_uint64),
                ("auxv", ctypes.c_void_p),
                ("auxv_size", ctypes.c_uint32),
                ("exe_fd", ctypes.c_uint32)]


def proc_stat_values():
    stat = open("/proc/self/stat", encoding="ascii").read()
    fields = stat[stat.rfind(")") + 2:].split()
    indexes = {"start_code": 23, "end_code": 24, "start_stack": 25,
               "start_data": 42, "end_data": 43, "start_brk": 44,
               "brk": 45, "arg_start": 46, "arg_end": 47,
               "env_start": 48, "env_end": 49}
    return {name: int(fields[index]) for name, index in indexes.items()}


def current_mm_map(exe_fd):
    values = proc_stat_values()
    auxv_data = open("/proc/self/auxv", "rb").read()
    auxv = ctypes.create_string_buffer(auxv_data)
    values["auxv"] = ctypes.addressof(auxv)
    values["auxv_size"] = len(auxv_data)
    values["exe_fd"] = exe_fd
    return PrctlMmMap(**values), auxv


def call_prctl(option, arg2, arg3=0, arg4=0, arg5=0):
    ctypes.set_errno(0)
    result = libc.prctl(option, arg2, arg3, arg4, arg5)
    return result, ctypes.get_errno()


def file_identity(path):
    st = os.stat(path)
    return st.st_dev, st.st_ino


def child_succeeds(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        except Exception as exc:
            print(f"child assertion failed: {exc}", file=sys.stderr)
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def exe_file_result(path):
    before = file_identity("/proc/self/exe")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        result, err = call_prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd)
    finally:
        os.close(fd)
    after = file_identity("/proc/self/exe")
    assert result == -1 and err == errno.EPERM, (result, err)
    assert after == before, (before, after)


def mm_map_result(path):
    before = file_identity("/proc/self/exe")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        mm, auxv = current_mm_map(fd)
        result, err = call_prctl(PR_SET_MM, PR_SET_MM_MAP,
                                 ctypes.addressof(mm), ctypes.sizeof(mm))
        assert auxv is not None
    finally:
        os.close(fd)
    after = file_identity("/proc/self/exe")
    assert result == -1 and err == errno.EPERM, (result, err)
    assert after == before, (before, after)


assert_frozen_runtime()

assert child_succeeds(lambda: exe_file_result(SHIRUDO)), \
    "PR_SET_MM_EXE_FILE was allowed for a non-Shirudo caller"
assert child_succeeds(lambda: exe_file_result(OTHER)), \
    "PR_SET_MM_EXE_FILE accepted an unrelated executable"
assert child_succeeds(lambda: mm_map_result(SHIRUDO)), \
    "PR_SET_MM_MAP was allowed for a non-Shirudo caller"
assert child_succeeds(lambda: mm_map_result(OTHER)), \
    "PR_SET_MM_MAP accepted an unrelated executable"


def invalid_fd_then_exec():
    result, err = call_prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, 1 << 30)
    assert result == -1 and err == errno.EPERM, (result, err)
    os.execve(SHIRUDO_COMMAND, [SHIRUDO_COMMAND, "status", "--json"],
              os.environ.copy())


assert child_succeeds(invalid_fd_then_exec), \
    "failed PR_SET_MM left state that blocked ordinary Shirudo execution"
print("PR_SET_MM identity guard passed")
