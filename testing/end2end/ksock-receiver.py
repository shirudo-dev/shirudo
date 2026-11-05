#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import pathlib
import socket
import sys


def main():
    ready, received = map(pathlib.Path, sys.argv[1:])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 19090))
        ready.write_text("ready\n")
        data, peer = server.recvfrom(65535)
        if data != b"shirudo ksock dummy\n":
            raise RuntimeError(f"unexpected ksock datagram from {peer}: {data!r}")
        received.write_bytes(data)
        print(f"received {len(data)} bytes from {peer}", flush=True)


if __name__ == "__main__":
    main()
