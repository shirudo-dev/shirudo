# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import errno
import os
import platform
import struct
import signal
import subprocess
import sys
import tempfile
import time

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)
libc.ptrace.restype = ctypes.c_long
libc.syscall.restype = ctypes.c_long


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


libc.process_vm_writev.argtypes = (ctypes.c_int, ctypes.POINTER(Iovec), ctypes.c_ulong,
                                  ctypes.POINTER(Iovec), ctypes.c_ulong, ctypes.c_ulong)
libc.process_vm_writev.restype = ctypes.c_ssize_t

class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort),
                ("filter", ctypes.POINTER(SockFilter))]


def allow_all_seccomp():
    instruction = SockFilter(6, 0, 0, 0x7fff0000)
    program = SockFprog(1, ctypes.pointer(instruction))
    assert libc.prctl(38, 1, 0, 0, 0) == 0, ("NO_NEW_PRIVS", ctypes.get_errno())
    assert libc.prctl(22, 2, ctypes.byref(program), 0, 0) == 0, \
        ("seccomp allow-all prerequisite", ctypes.get_errno())


def outside_exec_with_seccomp():
    allow_all_seccomp()
    os.execv(sys.executable, [sys.executable, "-c", "pass"])


def forbidden_exec_with_seccomp():
    allow_all_seccomp()
    try:
        os.execv(sys.argv[1], [sys.argv[1], "unexpected-exec"])
    except OSError as exc:
        assert exc.errno in (errno.EPERM, errno.EACCES), exc
    else:
        raise AssertionError("runtime exec succeeded under caller-controlled seccomp")


def forbidden_exec_while_traced():
    assert libc.ptrace(0, 0, None, None) == 0, ("TRACEME prerequisite", ctypes.get_errno())
    try:
        os.execv(sys.argv[1], [sys.argv[1], "unexpected-exec"])
    except OSError as exc:
        assert exc.errno in (errno.EPERM, errno.EACCES), exc
    else:
        raise AssertionError("runtime exec succeeded with a pre-existing tracer")


def child_check(fn):
    pid = os.fork()
    if not pid:
        try:
            fn()
        except BaseException as exc:
            print(f"pre-existing observer: {exc}", file=sys.stderr)
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if os.WIFSTOPPED(status):
        libc.ptrace(17, pid, None, None)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("trusted exec reached a ptrace stop")
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, (fn.__name__, status)


child_check(outside_exec_with_seccomp)
child_check(forbidden_exec_with_seccomp)
child_check(forbidden_exec_while_traced)


with tempfile.TemporaryDirectory() as work:
    ready = os.path.join(work, "ready")
    target = subprocess.Popen([sys.argv[1], "wait", ready])
    try:
        for _ in range(100):
            if os.path.isfile(ready):
                fields = open(ready, encoding="ascii").read().split()
                if len(fields) == 2:
                    break
            assert target.poll() is None, "trusted process exited early"
            time.sleep(0.05)
        else:
            raise AssertionError("trusted process did not become ready")
        pid, address = int(fields[0]), int(fields[1], 16)
        assert pid == target.pid
        ctypes.set_errno(0)
        result = libc.ptrace(16, pid, None, None)
        err = ctypes.get_errno()
        if result == 0:
            os.waitpid(pid, 0)
            libc.ptrace(17, pid, None, None)
        assert result == -1 and err in (errno.EPERM, errno.EACCES), ("ptrace", result, err)
        try:
            fd = os.open(f"/proc/{pid}/mem", os.O_WRONLY | os.O_CLOEXEC)
        except OSError as exc:
            assert exc.errno in (errno.EPERM, errno.EACCES), exc
        else:
            os.close(fd)
            raise AssertionError("writable /proc/pid/mem was opened")
        perf_syscall = {"x86_64": 298, "aarch64": 241, "riscv64": 241}[platform.machine()]
        attributes = ctypes.create_string_buffer(64)
        struct.pack_into("IIQQQQQ", attributes, 0, 1, 64, 0, 0, 0, 0, 1)
        for perf_pid, cpu in ((pid, -1),):
            ctypes.set_errno(0)
            event_fd = libc.syscall(perf_syscall, ctypes.byref(attributes),
                                     perf_pid, cpu, -1, 0)
            err = ctypes.get_errno()
            if event_fd >= 0:
                os.close(event_fd)
            assert event_fd == -1 and err in (errno.EPERM, errno.EACCES), \
                ("perf_event_open", perf_pid, cpu, event_fd, err)
        value = ctypes.c_ulong(0)
        source = Iovec(ctypes.addressof(value), ctypes.sizeof(value))
        destination = Iovec(address, ctypes.sizeof(value))
        ctypes.set_errno(0)
        result = libc.process_vm_writev(pid, ctypes.byref(source), 1,
                                        ctypes.byref(destination), 1, 0)
        err = ctypes.get_errno()
        assert result == -1 and err in (errno.EPERM, errno.EACCES), \
            ("process_vm_writev", result, err)
    finally:
        if target.poll() is None:
            target.send_signal(signal.SIGTERM)
        try:
            target.wait(timeout=3)
        except subprocess.TimeoutExpired:
            target.kill()
            target.wait(timeout=3)
print("trusted process memory guards passed")
