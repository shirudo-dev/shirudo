#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Generate activity that exercises every table of the kernel-obs upatch."""

import argparse
import ctypes
import errno
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import threading

WATCH_V4 = "203.0.113.10"
WATCH_V6 = "2001:db8::10"
BIND_PORT = 35353


def exec_event():
    with tempfile.TemporaryDirectory() as directory:
        executable = os.path.join(directory, "true")
        shutil.copyfile("/bin/true", executable)
        os.chmod(executable, 0o755)
        subprocess.run([executable], check=True)
        subprocess.run(["./end2end/exec-paths", directory], check=True)
        for method in ("execveat-empty", "fexecve"):
            fd_executable = os.path.join(directory, f"true-{method}")
            shutil.copyfile("/bin/true", fd_executable)
            os.chmod(fd_executable, 0o755)
            subprocess.run(["./end2end/exec-paths", f"--{method}",
                            fd_executable], check=True)
        dirfd_executable = os.path.join(directory, "true-execveat-dirfd")
        shutil.copyfile("/bin/true", dirfd_executable)
        os.chmod(dirfd_executable, 0o755)
        subprocess.run(["./end2end/exec-paths",
                        "--execveat-dirfd", directory,
                        os.path.basename(dirfd_executable)], check=True)
        dropped_uid_executable = os.path.join(directory, "true-drop-euid")
        shutil.copyfile("/bin/true", dropped_uid_executable)
        os.chmod(dropped_uid_executable, 0o755)
        os.chmod(directory, 0o755)
        subprocess.run(["./end2end/exec-paths",
                        "--drop-euid", dropped_uid_executable], check=True)
        subprocess.run(["./end2end/exec-paths", "--replace", executable],
                       check=True)


def tcp_event():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    accepted = []

    def accept_one():
        conn, _ = server.accept()
        accepted.append(conn.recv(1))
        conn.close()

    thread = threading.Thread(target=accept_one)
    thread.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(b"o")
    client.close()
    thread.join(3)
    server.close()
    if thread.is_alive() or not accepted:
        raise RuntimeError("TCP listener did not receive the test connection")


def udp_event():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    destination = receiver.getsockname()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"obs", destination)
    receiver.settimeout(3)
    payload, _ = receiver.recvfrom(16)
    sender.close()
    receiver.close()
    if payload != b"obs":
        raise RuntimeError("UDP listener received an unexpected payload")


def listen_event():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receiver.bind(("127.0.0.1", BIND_PORT))
    receiver.close()


def file_event():
    with open("/etc/shadow", "rb") as shadow:
        shadow.read(1)
    with open("/proc/self/environ", "rb") as environ:
        environ.read(1)


def watch_event():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.setblocking(False)
    rc = client.connect_ex((WATCH_V4, 80))
    client.close()
    if rc not in (0, errno.EINPROGRESS, errno.ENETUNREACH, errno.EHOSTUNREACH):
        raise RuntimeError(f"watched TCP connect returned errno {rc}")
    # A dual-stack socket, as a JVM uses, reaches the IPv4 entry as ::ffff:.
    client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client.setblocking(False)
    rc = client.connect_ex(("::ffff:" + WATCH_V4, 81))
    client.close()
    if rc not in (0, errno.EINPROGRESS, errno.ENETUNREACH, errno.EHOSTUNREACH):
        raise RuntimeError(f"watched mapped TCP connect returned errno {rc}")
    sender = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sender.sendto(b"obs", (WATCH_V6, 9))
    except OSError as error:
        if error.errno not in (errno.ENETUNREACH, errno.EHOSTUNREACH,
                               errno.EADDRNOTAVAIL):
            raise
    finally:
        sender.close()


def socket_events():
    expected = {"creations": [], "fd_pass": {}}

    def create(family, kind, protocol=0, required=False):
        try:
            sock = socket.socket(family, kind, protocol)
        except OSError:
            if required:
                raise
            return None
        expected["creations"].append({
            "family": family,
            "type": kind & 0xf,
            "protocol": protocol,
        })
        return sock

    raw = create(socket.AF_INET, socket.SOCK_RAW,
                 socket.IPPROTO_ICMP)
    expected["raw_created"] = raw is not None
    if raw:
        try:
            raw.sendto(b"\x08\x00\x00\x00\x12\x34\x00\x01",
                       ("127.0.0.1", 0))
        except OSError:
            pass
        raw.close()

    def family_module_loaded(*modules):
        return any(os.path.isdir(os.path.join("/sys/module", module))
                   for module in modules)

    packet_family = getattr(socket, "AF_PACKET", 17)
    sol_packet = getattr(socket, "SOL_PACKET", 263)
    eth_p_all = 0x0003
    packet_kinds = ((socket.SOCK_RAW, socket.SOCK_DGRAM)
                    if family_module_loaded("af_packet") else ())
    for kind in packet_kinds:
        packet = create(packet_family, kind, socket.htons(eth_p_all))
        if not packet:
            continue
        try:
            packet.bind(("lo", socket.htons(eth_p_all)))
        except OSError:
            pass
        try:
            packet.setsockopt(sol_packet, 10, 2)
            packet.setsockopt(sol_packet, 5,
                              struct.pack("=7I", 4096, 1, 2048, 2,
                                          100, 0, 0))
            packet.setsockopt(sol_packet, 13,
                              struct.pack("=4I", 4096, 1, 2048, 2))
        except OSError:
            pass
        try:
            packet.send(b"")
        except OSError:
            pass
        packet.close()

    xdp_family = getattr(socket, "AF_XDP", 44)
    xdp = (create(xdp_family, socket.SOCK_RAW)
           if family_module_loaded("xsk", "xdp_sock", "xdp") else None)
    if xdp:
        class SockaddrXDP(ctypes.Structure):
            _fields_ = [("family", ctypes.c_ushort),
                        ("flags", ctypes.c_ushort),
                        ("ifindex", ctypes.c_uint),
                        ("queue_id", ctypes.c_uint),
                        ("shared_umem_fd", ctypes.c_uint)]

        address = SockaddrXDP()
        address.family = xdp_family
        try:
            address.ifindex = socket.if_nametoindex("lo")
        except OSError:
            address.ifindex = 0
        libc = ctypes.CDLL(None, use_errno=True)
        libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p,
                              ctypes.c_uint]
        libc.sendto.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                ctypes.c_size_t, ctypes.c_int,
                                ctypes.c_void_p, ctypes.c_uint]
        libc.bind(xdp.fileno(), ctypes.byref(address),
                  ctypes.sizeof(address))
        libc.sendto(xdp.fileno(), None, 0, 0, ctypes.byref(address),
                    ctypes.sizeof(address))
        xdp.close()

    unix_types = (socket.SOCK_STREAM, socket.SOCK_DGRAM,
                  socket.SOCK_SEQPACKET)
    with tempfile.TemporaryDirectory() as directory:
        for index, kind in enumerate(unix_types):
            server = create(socket.AF_UNIX, kind, required=True)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
            path = os.path.join(directory, f"unix-{index}")
            server.bind(path)
            if kind == socket.SOCK_DGRAM:
                sender = create(socket.AF_UNIX, kind, required=True)
                sender.sendto(b"u", path)
                server.recvfrom(1)
                sender.close()
            else:
                server.listen(1)
                client = create(socket.AF_UNIX, kind, required=True)
                client.connect(path)
                accepted, _ = server.accept()
                client.send(b"u")
                client.shutdown(socket.SHUT_WR)
                accepted.recv(1)
                accepted.close()
                client.close()
            server.close()

    for kind in unix_types:
        try:
            left, right = socket.socketpair(socket.AF_UNIX, kind)
        except OSError:
            continue
        left.send(b"p")
        right.recv(1)
        left.close()
        right.close()

    netlink_family = getattr(socket, "AF_NETLINK", 16)
    netlink_protocol = getattr(socket, "NETLINK_ROUTE", 0)
    netlink = create(netlink_family, socket.SOCK_RAW, netlink_protocol,
                     required=True)
    netlink.bind((0, 0))
    sequence = os.getpid() & 0xffffffff
    request = struct.pack("=IHHII", 32, 18, 0x301, sequence, 0)
    request += struct.pack("=BBHiII", 0, 0, 0, 0, 0, 0)
    netlink.settimeout(2)
    netlink.send(request)
    netlink.recv(4096)
    netlink.close()

    vsock_family = getattr(socket, "AF_VSOCK", 40)
    vsock_types = (unix_types if family_module_loaded("vsock") else ())
    for kind in vsock_types:
        vsock = create(vsock_family, kind)
        if not vsock:
            continue
        try:
            vsock.bind((0xffffffff, 0))
        except OSError:
            pass
        try:
            if kind == socket.SOCK_DGRAM:
                vsock.sendto(b"", (2, 1))
            else:
                vsock.setblocking(False)
                vsock.connect_ex((2, 1))
        except OSError:
            pass
        vsock.close()

    flagged = getattr(socket, "SOCK_NONBLOCK", 0) | \
        getattr(socket, "SOCK_CLOEXEC", 0)
    if flagged:
        sock = create(socket.AF_INET, socket.SOCK_DGRAM | flagged)
        if sock:
            sock.close()

    inherited = create(socket.AF_INET, socket.SOCK_DGRAM, required=True)
    inherited.bind(("127.0.0.1", 0))
    owner_pid = os.getpid()
    child_pid = os.fork()
    if child_pid == 0:
        try:
            inherited.sendto(b"i", ("127.0.0.1", 9))
        finally:
            os._exit(0)
    _, status = os.waitpid(child_pid, 0)
    inherited.close()
    if os.waitstatus_to_exitcode(status) != 0:
        raise RuntimeError("inherited socket send failed")
    expected["fd_pass"] = {"owner_pid": owner_pid, "actor_pid": child_pid}
    print(json.dumps(expected))


def dns_wire_name(labels):
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("DNS labels must contain between 1 and 63 bytes")
    wire = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    if len(wire) > 255:
        raise ValueError("DNS wire name exceeds 255 bytes")
    return wire


def dns_name(name):
    return dns_wire_name([label.encode() for label in name.split(".")])


def dns_event():
    nameservers = []
    with open("/etc/resolv.conf", encoding="utf-8") as resolv:
        for line in resolv:
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                nameservers.append(fields[1])
    if not nameservers:
        raise RuntimeError("/etc/resolv.conf has no nameserver")

    transaction = random.randrange(1, 65535)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0)
    query += dns_name("example.com") + struct.pack("!HH", 1, 1)
    last_error = None
    for nameserver in nameservers:
        family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(4)
        try:
            sock.sendto(query, (nameserver, 53))
            response, _ = sock.recvfrom(4096)
            if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
                raise RuntimeError("DNS response transaction ID mismatch")
            if not (struct.unpack("!H", response[2:4])[0] & 0x8000):
                raise RuntimeError("DNS response flag is not set")
            return
        except (OSError, RuntimeError) as error:
            last_error = error
        finally:
            sock.close()
    raise RuntimeError(f"DNS query failed: {last_error}")


def local_dns_exchange(wire_name, answers):
    transaction = random.randrange(1, 65535)
    question = wire_name + struct.pack("!HH", 1, 1)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    errors = []

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(3)
    server.bind(("127.0.0.1", 53))

    def answer_one():
        try:
            request, peer = server.recvfrom(4096)
            if request != query:
                raise RuntimeError("local DNS server received an unexpected query")
            header = struct.pack("!HHHHHH", transaction, 0x8180, 1,
                                 len(answers), 0, 0)
            server.sendto(header + question + b"".join(answers), peer)
        except Exception as error:  # Propagate server-thread failures below.
            errors.append(error)

    thread = threading.Thread(target=answer_one)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    try:
        client.sendto(query, ("127.0.0.1", 53))
        response, _ = client.recvfrom(4096)
        if len(response) < 12 or struct.unpack("!H", response[:2])[0] != transaction:
            raise RuntimeError("local DNS response transaction ID mismatch")
    finally:
        client.close()
        thread.join(3)
        server.close()
    if thread.is_alive():
        raise RuntimeError("local DNS server did not finish")
    if errors:
        raise RuntimeError(f"local DNS server failed: {errors[0]}")


def dns_long_event():
    answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 60, 4,
                                       socket.inet_aton("203.0.113.10"))
    local_dns_exchange(dns_name(".".join(["a"] * 127)), [answer])


def dns_many_answers_event():
    unsupported = b"\xc0\x0c" + struct.pack("!HHIHB", 16, 1, 60, 1, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 60, 4,
                                       socket.inet_aton("203.0.113.75"))
    local_dns_exchange(dns_name("many.example"), [unsupported] * 74 + [answer])


# Labels holding a NUL, a dot, UTF-8 and a NUL alone, whose bytes
# kernel-obs records as '?'.
ODD_NAMES = (
    ([b"ww\0w", b"evil", b"example"], "203.0.113.81"),
    ([b"www.good", b"example"], "203.0.113.82"),
    ([b"caf\xc3\xa9", b"example"], "203.0.113.83"),
    ([b"\0", b"evil", b"example"], "203.0.113.84"),
)


def dns_odd_event():
    for labels, address in ODD_NAMES:
        answer = b"\xc0\x0c" + struct.pack("!HHIH4s", 1, 1, 60, 4,
                                           socket.inet_aton(address))
        local_dns_exchange(dns_wire_name(labels), [answer])


EVENTS = {
    "exec": exec_event,
    "tcp": tcp_event,
    "udp": udp_event,
    "sockets": socket_events,
    "dns": dns_event,
    "listen": listen_event,
    "file": file_event,
    "watch": watch_event,
    "dns-long": dns_long_event,
    "dns-many": dns_many_answers_event,
    "dns-odd": dns_odd_event,
}
ALL = ("exec", "tcp", "udp", "dns", "listen", "file")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("all",) + tuple(EVENTS))
    mode = parser.parse_args().mode
    for name in (ALL if mode == "all" else (mode,)):
        EVENTS[name]()


if __name__ == "__main__":
    main()
