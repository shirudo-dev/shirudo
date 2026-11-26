#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# idle-agent.py <jar> -- write a jar whose one class, shirudo.test.Idle,
# is a Java agent that does nothing, at JVM start and by attach, and a
# main class that sleeps ten minutes: a JVM to watch without a JDK.

import struct
import sys
import zipfile

CLASS = "shirudo/test/Idle"
AGENT_DESC = "(Ljava/lang/String;Ljava/lang/instrument/Instrumentation;)V"


def utf8(text):
    data = text.encode()
    return struct.pack(">BH", 1, len(data)) + data


def code(max_stack, max_locals, insns):
    body = struct.pack(">HHI", max_stack, max_locals, len(insns)) + insns
    body += struct.pack(">HH", 0, 0)
    return struct.pack(">HI", 7, len(body)) + body


def method(name, desc, attr):
    return struct.pack(">HHHH", 0x0009, name, desc, 1) + attr


def idle_class():
    pool = [
        utf8(CLASS),                        # 1
        struct.pack(">BH", 7, 1),           # 2 class Idle
        utf8("java/lang/Object"),           # 3
        struct.pack(">BH", 7, 3),           # 4 class Object
        utf8("premain"),                    # 5
        utf8(AGENT_DESC),                   # 6
        utf8("Code"),                       # 7
        utf8("main"),                       # 8
        utf8("([Ljava/lang/String;)V"),     # 9
        utf8("java/lang/Thread"),           # 10
        struct.pack(">BH", 7, 10),          # 11 class Thread
        utf8("sleep"),                      # 12
        utf8("(J)V"),                       # 13
        struct.pack(">BHH", 12, 12, 13),    # 14 sleep:(J)V
        struct.pack(">BHH", 10, 11, 14),    # 15 Thread.sleep
        struct.pack(">BQ", 5, 600000),      # 16 and 17, a long
        utf8("agentmain"),                  # 18
    ]
    ret = bytes([0xb1])
    sleep = bytes([0x14, 0x00, 16, 0xb8, 0x00, 15, 0xb1])
    out = struct.pack(">IHHH", 0xcafebabe, 0, 52, 19) + b"".join(pool)
    out += struct.pack(">HHHHHH", 0x0021, 2, 4, 0, 0, 3)
    out += method(5, 6, code(0, 2, ret))
    out += method(18, 6, code(0, 2, ret))
    out += method(8, 9, code(2, 1, sleep))
    return out + struct.pack(">H", 0)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: idle-agent.py <jar>")
    manifest = ("Manifest-Version: 1.0\n"
                "Premain-Class: shirudo.test.Idle\n"
                "Agent-Class: shirudo.test.Idle\n"
                "Main-Class: shirudo.test.Idle\n\n")
    with zipfile.ZipFile(sys.argv[1], "w") as z:
        z.writestr("META-INF/MANIFEST.MF", manifest)
        z.writestr(CLASS + ".class", idle_class())


if __name__ == "__main__":
    main()
