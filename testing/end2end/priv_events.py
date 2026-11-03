#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import ctypes
import errno
import json
import os
import platform
import shutil
import signal
import socket
import struct
import sys

from snapshots import read_documents

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4
MAP_PRIVATE = 2
MAP_ANONYMOUS = 0x20
BPF_MAP_GET_NEXT_ID = 12
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PR_SET_NAME = 15
LSM_SETID_RES = 4

SYSCALLS = {
    "x86_64": {"bpf": 321, "finit_module": 313, "init_module": 175},
    "aarch64": {"bpf": 280, "finit_module": 273, "init_module": 105},
    "riscv64": {"bpf": 280, "finit_module": 273, "init_module": 105},
}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.ptrace.restype = ctypes.c_long
libc.prctl.restype = ctypes.c_int
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]


def syscall_numbers():
    machine = platform.machine()
    if machine not in SYSCALLS:
        raise RuntimeError(f"unsupported syscall architecture: {machine}")
    return SYSCALLS[machine]


def file_identity(path):
    info = os.stat(path)
    return {"dev": (os.major(info.st_dev) << 20) | os.minor(info.st_dev),
            "ino": info.st_ino}


def identity_matches(observed, expected):
    return (int(observed["dev"]) == int(expected["dev"]) and
            int(observed["ino"]) == int(expected["ino"]))

def true_name():
    return os.path.basename(os.path.realpath("/bin/true"))


def executable_identity():
    return file_identity("/proc/self/exe")


def setuid_event():
    os.seteuid(65534)
    try:
        os.seteuid(0)
    finally:
        if os.geteuid() != 0:
            os.seteuid(0)


def ptrace_event():
    ready_read, ready_write = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(ready_read)
        if libc.prctl(PR_SET_NAME, ctypes.c_char_p(b"priv-child"), 0, 0, 0) < 0:
            os.write(ready_write, b"0")
            os._exit(1)
        os.write(ready_write, b"1")
        os.close(ready_write)
        while True:
            signal.pause()
    os.close(ready_write)
    try:
        if os.read(ready_read, 1) != b"1":
            raise RuntimeError("ptrace child failed to set its process name")
        os.close(ready_read)
        ctypes.set_errno(0)
        if libc.ptrace(PTRACE_ATTACH, child, None, None) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        waited, status = os.waitpid(child, os.WUNTRACED)
        if waited != child or not os.WIFSTOPPED(status):
            raise RuntimeError("ptrace child did not stop after attach")
        if libc.ptrace(PTRACE_DETACH, child, None, None) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        try:
            os.close(ready_read)
        except OSError:
            pass
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
    return child


def userns_event():
    children = []
    for _ in range(2):
        child = os.fork()
        if child == 0:
            try:
                os.unshare(os.CLONE_NEWUSER)
            except Exception:
                os._exit(1)
            os._exit(0)
        children.append(child)
        waited, status = os.waitpid(child, 0)
        if waited != child or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise RuntimeError("user namespace creation failed")
    return children


def mount_event(workdir):
    path = os.path.join(workdir, "mountpoint")
    os.mkdir(path)
    encoded = os.fsencode(path)
    if libc.mount(b"none", encoded, b"tmpfs", 0, None) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        return path
    finally:
        if libc.umount2(encoded, 0) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def module_load_events(workdir):
    path = os.path.join(workdir, "invalid-module.ko")
    with open(path, "wb") as image:
        image.write(b"not a kernel module")
    fd = os.open(path, os.O_RDONLY)
    try:
        number = syscall_numbers()["finit_module"]
        ctypes.set_errno(0)
        result = libc.syscall(number, ctypes.c_int(fd),
                              ctypes.c_char_p(b""), ctypes.c_int(0))
        if result >= 0:
            raise RuntimeError("invalid module image was unexpectedly accepted")
    finally:
        os.close(fd)

    image = ctypes.create_string_buffer(b"\x7fELF" + b"\0" * 123)
    number = syscall_numbers()["init_module"]
    ctypes.set_errno(0)
    result = libc.syscall(number, ctypes.byref(image),
                          ctypes.c_ulong(ctypes.sizeof(image)),
                          ctypes.c_char_p(b""))
    if result >= 0:
        raise RuntimeError("invalid init_module image was unexpectedly accepted")
    return path


def module_request_event():
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 31)
    except OSError:
        return
    sock.close()
    raise RuntimeError("test Netlink protocol unexpectedly opened")


def bpf_event():
    attr = bytearray(72)
    struct.pack_into("=IIIIIII", attr, 0, 1, 4, 4, 1, 0, 0, 0)
    attr[28:44] = b"privtest\0".ljust(16, b"\0")
    buf = ctypes.create_string_buffer(bytes(attr))
    number = syscall_numbers()["bpf"]
    ctypes.set_errno(0)
    result = libc.syscall(number, ctypes.c_int(0), ctypes.byref(buf),
                          ctypes.c_uint(len(attr)))
    if result >= 0:
        os.close(result)
        raise RuntimeError("unsigned BPF map creation unexpectedly succeeded")
    error = ctypes.get_errno()
    if error not in (errno.EPERM, errno.EACCES):
        raise OSError(error, os.strerror(error))


def bpf_readonly_event():
    attr = bytearray(72)
    buf = ctypes.create_string_buffer(bytes(attr))
    number = syscall_numbers()["bpf"]
    ctypes.set_errno(0)
    result = libc.syscall(number, ctypes.c_int(BPF_MAP_GET_NEXT_ID),
                          ctypes.byref(buf), ctypes.c_uint(len(attr)))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def mmap_exec_event():
    fd = os.open("/bin/true", os.O_RDONLY)
    try:
        address = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_EXEC,
                            MAP_PRIVATE, fd, 0)
        if address == ctypes.c_void_p(-1).value:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.munmap(address, PAGE_SIZE) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(fd)


def vma_size(address):
    with open("/proc/self/maps", encoding="ascii") as mappings:
        for line in mappings:
            start, end = (int(bound, 16) for bound in
                          line.split(None, 1)[0].split("-"))
            if start <= address < end:
                return end - start
    raise RuntimeError("mmap address is missing from /proc/self/maps")


def mprotect_exec_event():
    address = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if address == ctypes.c_void_p(-1).value:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    size = vma_size(address)
    try:
        if libc.mprotect(address, PAGE_SIZE, PROT_READ | PROT_EXEC) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        if libc.munmap(address, PAGE_SIZE) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    return size


def nonexec_mapping_events():
    fd = os.open("/bin/true", os.O_RDONLY)
    try:
        address = libc.mmap(None, PAGE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0)
        if address == ctypes.c_void_p(-1).value:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.munmap(address, PAGE_SIZE) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(fd)
    address = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    if address == ctypes.c_void_p(-1).value:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    try:
        if libc.mprotect(address, PAGE_SIZE, PROT_READ) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        if libc.munmap(address, PAGE_SIZE) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def existing_exec_mapping_event():
    fd = os.open("/bin/true", os.O_RDONLY)
    try:
        address = libc.mmap(None, PAGE_SIZE, PROT_READ | PROT_EXEC,
                            MAP_PRIVATE, fd, 0)
        if address == ctypes.c_void_p(-1).value:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.mprotect(address, PAGE_SIZE, PROT_READ | PROT_EXEC) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if libc.munmap(address, PAGE_SIZE) < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        os.close(fd)


def write_expected(path, expected):
    with open(path, "w", encoding="utf-8") as output:
        json.dump(expected, output)


def expected_identity():
    return {"pid": os.getpid(), "identity": executable_identity()}


def serve(request_path, response_path, expected_path):
    with open(request_path, encoding="utf-8") as requests:
        with open(response_path, "w", encoding="utf-8", buffering=1) as responses:
            for request in requests:
                try:
                    command = request.strip()
                    if command == "negative":
                        nonexec_mapping_events()
                        write_expected(expected_path, expected_identity())
                    elif command == "existing-exec":
                        existing_exec_mapping_event()
                        write_expected(expected_path, expected_identity())
                    elif command == "generate":
                        generate(expected_path)
                    elif command == "module-request":
                        module_request_event()
                        with open(expected_path, encoding="utf-8") as source:
                            expected = json.load(source)
                        expected["module_request"] = True
                        write_expected(expected_path, expected)
                    else:
                        raise ValueError(f"unknown event command: {command}")
                except Exception as error:
                    responses.write(f"error: {error}\n")
                else:
                    responses.write("ok\n")


def generate(expected_path):
    workdir = os.environ["SHIRUDO_TEST_WORK_DIR"]
    os.makedirs(workdir, exist_ok=True)
    pid = os.getpid()
    identity = executable_identity()
    with open("/proc/self/comm", encoding="utf-8") as comm_file:
        comm = comm_file.read().strip()
    setuid_event()
    ptrace_child = ptrace_event()
    children = userns_event()
    mountpoint = mount_event(workdir)
    module_path = module_load_events(workdir)
    bpf_event()
    bpf_readonly_event()
    mmap_exec_event()
    mprotect_size = mprotect_exec_event()
    with open(expected_path, "w", encoding="utf-8") as output:
        json.dump({"pid": pid, "identity": identity, "comm": comm,
                   "ptrace_child": ptrace_child,
                   "userns_children": children,
                   "mountpoint": mountpoint,
                   "module_path": module_path,
                   "mprotect_size": mprotect_size,
                   "module_request": False}, output)


def records_from(path):
    documents = read_documents(path)
    document = next(doc for doc in documents if doc.get("map") == "priv")
    return document["records"]


def check_negative(path, expected_path):
    with open(expected_path, encoding="utf-8") as source:
        expected = json.load(source)
    records = records_from(path)
    identity = expected["identity"]
    selected = [record for record in records
                if int(record["executable"]["dev"]) == identity["dev"] and
                int(record["executable"]["ino"]) == identity["ino"]]
    assert not any(record["kind"] in ("mmap_exec", "mprotect_exec",
                                      "cred_anomaly")
                   for record in selected), selected


def check_existing_exec(path, expected_path):
    with open(expected_path, encoding="utf-8") as source:
        expected = json.load(source)
    identity = expected["identity"]
    records = records_from(path)
    selected = [record for record in records
                if int(record["executable"]["dev"]) == identity["dev"] and
                int(record["executable"]["ino"]) == identity["ino"]]
    assert len(selected) == 1, selected
    mmap_exec = selected[0]
    assert mmap_exec["kind"] == "mmap_exec", selected
    assert mmap_exec["name"] == true_name(), mmap_exec
    assert mmap_exec["subtype"] == (PROT_READ | PROT_EXEC), mmap_exec
    assert int(mmap_exec["aux"]) == MAP_PRIVATE, mmap_exec
    assert int(mmap_exec["count"]) == 1, mmap_exec


def check_anomaly(expected_path, records_path):
    with open(expected_path, encoding="utf-8") as source:
        expected = json.load(source)
    records = records_from(records_path)
    anomalies = [record for record in records
                 if record["kind"] == "cred_anomaly"]
    assert len(anomalies) == 1, anomalies
    anomaly = anomalies[0]
    assert anomaly["subtype"] == 1 and anomaly["euid"] == 0, anomaly
    assert anomaly["uid"] == 0 and int(anomaly["aux"]) == 0, anomaly
    assert identity_matches(anomaly["executable"], expected["identity"]), \
        (expected["identity"], anomaly)
    assert anomaly["pid"] == expected["pid"], anomaly
    assert anomaly["name"], anomaly
    assert int(anomaly["count"]) == 1, anomaly
    assert int(anomaly["pid"]) > 0, anomaly
    assert int(anomaly["first_seen_unix_nano"]) > 0, anomaly
    assert int(anomaly["last_seen_unix_nano"]) >= \
        int(anomaly["first_seen_unix_nano"]), anomaly


def anomaly_event(expected_path):
    executable = os.path.join(os.path.dirname(expected_path), "true")
    shutil.copyfile("/bin/true", executable)
    os.chmod(executable, 0o755)
    write_expected(expected_path,
                   {"pid": os.getpid(), "identity": file_identity(executable)})
    os.execv(executable, [executable])


def check_exec_unknown(path):
    documents = read_documents(path)
    document = next(doc for doc in documents if doc.get("map") == "exec")
    records = document["records"]
    unknown = [record for record in records
               if record["path"].endswith("/false")]
    assert unknown, records
    assert any("caller" not in record and not record["caller_inferred"]
               for record in unknown), unknown


def check_positive(expected_path, records_path):
    with open(expected_path, encoding="utf-8") as source:
        expected = json.load(source)
    records = records_from(records_path)
    kinds = {"setuid_root", "ptrace_attach", "mount", "kernel_read_file",
             "kernel_load_data", "module_request", "userns_create", "bpf",
             "mmap_exec", "mprotect_exec"}
    if not expected["module_request"]:
        kinds.remove("module_request")
    identity = expected["identity"]
    selected = [record for record in records
                if record["kind"] in kinds and
                int(record["executable"]["dev"]) == identity["dev"] and
                int(record["executable"]["ino"]) == identity["ino"]]
    found = {record["kind"] for record in selected}
    if found != kinds:
        available = [
            {"kind": record.get("kind"),
             "executable": record.get("executable"),
             "pid": record.get("pid")}
            for record in records if record.get("kind") in kinds
        ]
        raise AssertionError({"missing": sorted(kinds - found),
                              "expected_executable": identity,
                              "available_records": available})
    assert not any(record["kind"] == "cred_anomaly"
                   for record in records), records
    for record in selected:
        assert int(record["count"]) > 0, record
        assert int(record["pid"]) > 0, record
        assert int(record["first_seen_unix_nano"]) > 0, record
        assert int(record["last_seen_unix_nano"]) >= \
            int(record["first_seen_unix_nano"]), record
    assert len({str(record["cgroup_id"]) for record in selected}) == 1, selected

    def kind(name):
        matches = [record for record in selected if record["kind"] == name]
        assert len(matches) == 1, (name, matches)
        return matches

    setuid = kind("setuid_root")[0]
    assert setuid["subtype"] == LSM_SETID_RES, setuid
    assert setuid["euid"] == 65534 and setuid["uid"] == 0, setuid
    assert int(setuid["aux"]) == 0, setuid
    assert setuid["name"] == expected["comm"], setuid
    assert setuid["pid"] == expected["pid"], setuid
    assert int(setuid["count"]) == 1, setuid

    ptrace = kind("ptrace_attach")[0]
    assert ptrace["name"] == "priv-child", ptrace
    assert ptrace["subtype"] & 2, ptrace
    assert int(ptrace["aux"]) == expected["ptrace_child"], ptrace
    assert ptrace["pid"] == expected["pid"], ptrace
    assert int(ptrace["count"]) == 1, ptrace

    mount = kind("mount")[0]
    assert mount["name"] == "tmpfs", mount
    assert mount["detail"] == expected["mountpoint"], mount
    assert mount["subtype"] == 0 and int(mount["aux"]) == 0, mount
    assert mount["pid"] == expected["pid"] and int(mount["count"]) == 1, mount

    kernel_read = kind("kernel_read_file")[0]
    assert kernel_read["name"] == "invalid-module.ko", kernel_read
    assert kernel_read["detail"] == expected["module_path"], kernel_read
    assert kernel_read["subtype"] == 2, kernel_read
    kernel_load = kind("kernel_load_data")
    assert len(kernel_load) == 1, kernel_load
    assert kernel_load[0]["subtype"] == 2, kernel_load
    assert int(kernel_load[0]["count"]) >= 1, kernel_load

    if expected["module_request"]:
        module_request = kind("module_request")[0]
        assert module_request["name"] == "net-pf-16-proto-31", module_request
        assert module_request["subtype"] == 0 and \
            int(module_request["aux"]) == 0, module_request
        assert module_request["pid"] == expected["pid"], module_request

    userns = kind("userns_create")[0]
    assert int(userns["count"]) == 2, userns
    assert userns["pid"] in expected["userns_children"], userns
    assert userns["subtype"] == 0 and userns["euid"] == 0, userns

    bpf = kind("bpf")[0]
    assert bpf["subtype"] == 0, bpf
    assert bpf["pid"] == expected["pid"], bpf
    assert int(bpf["aux"]) == 0 and int(bpf["count"]) == 1, bpf
    map_creates = [record for record in records
                   if record["kind"] == "bpf" and record["subtype"] == 0 and
                   identity_matches(record["executable"], identity)]
    assert len(map_creates) == 1, map_creates
    assert identity_matches(map_creates[0]["executable"], identity), map_creates
    assert not any(record["kind"] == "bpf" and
                   record["subtype"] == BPF_MAP_GET_NEXT_ID and
                   identity_matches(record["executable"], identity)
                   for record in records), records

    mmap_exec = kind("mmap_exec")[0]
    assert mmap_exec["subtype"] == (PROT_READ | PROT_EXEC), mmap_exec
    assert mmap_exec["name"] == true_name(), mmap_exec
    assert int(mmap_exec["aux"]) == MAP_PRIVATE, mmap_exec
    mprotect_exec = kind("mprotect_exec")[0]
    assert mprotect_exec["subtype"] == (PROT_READ | PROT_EXEC), mprotect_exec
    assert mprotect_exec["name"] == "anonymous", mprotect_exec
    assert int(mprotect_exec["aux"]) == expected["mprotect_size"], mprotect_exec


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: priv_events.py serve IN OUT EXPECTED | "
                         "negative | generate FILE | "
                         "check EXPECTED NDJSON | check-negative NDJSON | "
                         "check-anomaly EXPECTED NDJSON | "
                         "check-exec-unknown NDJSON")
    mode = sys.argv[1]
    if mode == "serve" and len(sys.argv) == 5:
        serve(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "negative":
        nonexec_mapping_events()
    elif mode == "generate" and len(sys.argv) == 3:
        generate(sys.argv[2])
    elif mode == "check" and len(sys.argv) == 4:
        check_positive(sys.argv[2], sys.argv[3])
    elif mode == "check-negative" and len(sys.argv) == 4:
        check_negative(sys.argv[2], sys.argv[3])
    elif mode == "check-existing-exec" and len(sys.argv) == 4:
        check_existing_exec(sys.argv[2], sys.argv[3])
    elif mode == "check-anomaly" and len(sys.argv) == 4:
        check_anomaly(sys.argv[2], sys.argv[3])
    elif mode == "anomaly" and len(sys.argv) == 3:
        anomaly_event(sys.argv[2])
    elif mode == "check-exec-unknown" and len(sys.argv) == 3:
        check_exec_unknown(sys.argv[2])
    else:
        raise SystemExit("invalid priv_events.py arguments")


if __name__ == "__main__":
    main()
