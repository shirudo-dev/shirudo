#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""What t9114 runs in a node, in and out of the app-sandbox upatch.

    app_sandbox_probe.py setup <dir>   make the files the checks work on
    app_sandbox_probe.py run <dir>     print "<check> allowed|denied" for
                                       each operation the sandbox rules on

A check is denied when the kernel refuses it with EACCES, and allowed
with any other outcome: a connection nobody accepts was still let out.
"""

import errno
import os
import shutil
import socket
import subprocess
import sys

# TEST-NET-1 and the IPv6 documentation prefix: routed nowhere.
REMOTE_V4 = "192.0.2.1"
REMOTE_V6 = "2001:db8::1"
PORT = 9


def setup(work):
    files = os.path.join(work, "files")
    shutil.rmtree(files, ignore_errors=True)
    os.mkdir(files)
    for name in ("existing.php", "moved.php", "cut.php", "note.txt", "plain.txt"):
        with open(os.path.join(files, name), "w") as stream:
            stream.write("data\n")


def execute(path):
    subprocess.run([path], check=True)


def connect(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setblocking(False)
        sock.connect((address, PORT))


def send(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"probe", (address, PORT))


def raw_socket():
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()


def create(path):
    open(path, "x").close()


def write(path):
    open(path, "r+").close()


def read(path):
    open(path).close()


def checks(work):
    def f(name):
        return os.path.join(work, "files", name)

    return [
        ("exec-helper", lambda: execute(os.path.join(work, "helper"))),
        ("exec-other", lambda: execute(os.path.join(work, "other"))),
        ("connect-loopback", lambda: connect(socket.AF_INET, "127.0.0.1")),
        ("connect-loopback-v6", lambda: connect(socket.AF_INET6, "::1")),
        ("connect-loopback-mapped",
         lambda: connect(socket.AF_INET6, "::ffff:127.0.0.1")),
        ("connect-remote", lambda: connect(socket.AF_INET, REMOTE_V4)),
        ("connect-remote-v6", lambda: connect(socket.AF_INET6, REMOTE_V6)),
        ("connect-remote-mapped",
         lambda: connect(socket.AF_INET6, "::ffff:" + REMOTE_V4)),
        ("send-loopback", lambda: send(socket.AF_INET, "127.0.0.1")),
        ("send-remote", lambda: send(socket.AF_INET, REMOTE_V4)),
        ("send-remote-v6", lambda: send(socket.AF_INET6, REMOTE_V6)),
        ("raw-socket", raw_socket),
        ("create-txt", lambda: create(f("new.txt"))),
        ("create-php", lambda: create(f("new.php"))),
        ("create-exact", lambda: create(f("core"))),
        ("create-longer", lambda: create(f("cores"))),
        ("mkdir-php", lambda: os.mkdir(f("dir.php"))),
        ("symlink-php", lambda: os.symlink("note.txt", f("symlink.php"))),
        ("link-php", lambda: os.link(f("note.txt"), f("link.php"))),
        ("rename-txt", lambda: os.rename(f("plain.txt"), f("renamed.txt"))),
        ("rename-to-php", lambda: os.rename(f("note.txt"), f("note.php"))),
        ("rename-from-php", lambda: os.rename(f("moved.php"), f("moved.txt"))),
        ("read-php", lambda: read(f("existing.php"))),
        ("write-php", lambda: write(f("existing.php"))),
        ("truncate-php", lambda: os.truncate(f("cut.php"), 0)),
        ("write-txt", lambda: write(f("new.txt"))),
    ]


def run(work):
    for name, check in checks(work):
        try:
            check()
            verdict = "allowed"
        except OSError as error:
            verdict = "denied" if error.errno == errno.EACCES else "allowed"
        print(name, verdict)


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("setup", "run"):
        sys.exit(__doc__)
    {"setup": setup, "run": run}[sys.argv[1]](sys.argv[2])


if __name__ == "__main__":
    main()
