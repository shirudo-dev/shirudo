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

import ctypes
import errno
import os
import shutil
import signal
import socket
import subprocess
import sys
import time

# TEST-NET-1 and the IPv6 documentation prefix: routed nowhere.
REMOTE_V4 = "192.0.2.1"
REMOTE_V6 = "2001:db8::1"
IMDS_V4 = "169.254.169.254"
IMDS_V6 = "fd00:ec2::254"
LINKLOCAL_OTHER = "169.254.1.1"
PORT = 9
AF_ALG = 38
AF_VSOCK = 40
CLONE_NEWUSER = 0x10000000


def setup(work):
    files = os.path.join(work, "files")
    shutil.rmtree(files, ignore_errors=True)
    os.mkdir(files)
    for name in ("existing.php", "moved.php", "cut.php", "note.txt", "plain.txt", ".env"):
        with open(os.path.join(files, name), "w") as stream:
            stream.write("data\n")
    ssh_dir = os.path.join(files, ".ssh")
    os.mkdir(ssh_dir)
    with open(os.path.join(ssh_dir, "id_rsa"), "w") as stream:
        stream.write("secret\n")


def execute(path):
    subprocess.run([path], check=True)


def exec_memfd():
    fd = os.memfd_create("probe", 0)
    try:
        with open("/usr/bin/true", "rb") as stream:
            os.write(fd, stream.read())
        os.lseek(fd, 0, os.SEEK_SET)
        pid = os.fork()
        if pid == 0:
            try:
                os.execve(fd, ["probe"], {})
            except OSError as error:
                os._exit(error.errno or 1)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
            raise OSError(os.WEXITSTATUS(status), "exec-memfd")
    finally:
        os.close(fd)


def connect(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setblocking(False)
        sock.connect((address, PORT))


def connect_unix(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.setblocking(False)
        sock.connect(path)


def send(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"probe", (address, PORT))


def raw_socket():
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP).close()


def family_socket(family, sock_type):
    socket.socket(family, sock_type, 0).close()


def userns_create():
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        rc = libc.unshare(CLONE_NEWUSER)
        os._exit(0 if rc == 0 else (ctypes.get_errno() or 1))
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status) and os.WEXITSTATUS(status) != 0:
        raise OSError(os.WEXITSTATUS(status), "userns-create")


def ptrace_other():
    pid = os.fork()
    if pid == 0:
        time.sleep(10)
        os._exit(0)
    try:
        open(f"/proc/{pid}/mem", "rb").close()
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


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
        ("exec-helper-a", lambda: execute(os.path.join(work, "helper-a"))),
        ("exec-helper-b", lambda: execute(os.path.join(work, "helper-b"))),
        ("exec-helper-link",
         lambda: execute(os.path.join(work, "helper-link"))),
        ("exec-other", lambda: execute(os.path.join(work, "other"))),
        ("exec-memfd", exec_memfd),
        ("connect-loopback", lambda: connect(socket.AF_INET, "127.0.0.1")),
        ("connect-loopback-v6", lambda: connect(socket.AF_INET6, "::1")),
        ("connect-loopback-mapped",
         lambda: connect(socket.AF_INET6, "::ffff:127.0.0.1")),
        ("connect-remote", lambda: connect(socket.AF_INET, REMOTE_V4)),
        ("connect-remote-v6", lambda: connect(socket.AF_INET6, REMOTE_V6)),
        ("connect-remote-mapped",
         lambda: connect(socket.AF_INET6, "::ffff:" + REMOTE_V4)),
        ("connect-imds", lambda: connect(socket.AF_INET, IMDS_V4)),
        ("connect-imds-mapped",
         lambda: connect(socket.AF_INET6, "::ffff:" + IMDS_V4)),
        ("connect-imds-v6", lambda: connect(socket.AF_INET6, IMDS_V6)),
        ("connect-linklocal-other",
         lambda: connect(socket.AF_INET, LINKLOCAL_OTHER)),
        ("send-loopback", lambda: send(socket.AF_INET, "127.0.0.1")),
        ("send-remote", lambda: send(socket.AF_INET, REMOTE_V4)),
        ("send-remote-v6", lambda: send(socket.AF_INET6, REMOTE_V6)),
        ("send-imds", lambda: send(socket.AF_INET, IMDS_V4)),
        ("raw-socket", raw_socket),
        ("vsock-socket", lambda: family_socket(AF_VSOCK, socket.SOCK_STREAM)),
        ("alg-socket", lambda: family_socket(AF_ALG, socket.SOCK_SEQPACKET)),
        ("unix-docker", lambda: connect_unix(f("docker.sock"))),
        ("unix-docker-symlink", lambda: connect_unix(f("alias.sock"))),
        ("unix-ok", lambda: connect_unix(f("ok.sock"))),
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
        ("read-env", lambda: read(f(".env"))),
        ("read-ssh-key", lambda: read(f(".ssh/id_rsa"))),
        ("link-env", lambda: os.link(f(".env"), f("env-link.txt"))),
        ("rename-ssh-key",
         lambda: os.rename(f(".ssh/id_rsa"), f("stolen-key.txt"))),
        ("write-php", lambda: write(f("existing.php"))),
        ("truncate-php", lambda: os.truncate(f("cut.php"), 0)),
        ("write-txt", lambda: write(f("new.txt"))),
        ("userns-create", userns_create),
        ("ptrace-other", ptrace_other),
        ("ptrace-self", lambda: read("/proc/self/stat")),
    ]


def run(work):
    files = os.path.join(work, "files")
    listeners = []
    try:
        for name in ("docker.sock", "ok.sock"):
            path = os.path.join(files, name)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(path)
            sock.listen(1)
            listeners.append(sock)
        os.symlink("docker.sock", os.path.join(files, "alias.sock"))
        for name, check in checks(work):
            try:
                check()
                verdict = "allowed"
            except OSError as error:
                verdict = "denied" if error.errno == errno.EACCES else "allowed"
            print(name, verdict)
    finally:
        for sock in listeners:
            sock.close()


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("setup", "run"):
        sys.exit(__doc__)
    {"setup": setup, "run": run}[sys.argv[1]](sys.argv[2])


if __name__ == "__main__":
    main()
