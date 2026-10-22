# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
header = (root / "vendor/linux/vmlinux.h").read_text()
fields = {"enabled": "\tint mode;\n", "disabled": ""}[sys.argv[1]]
header, count = re.subn(r"(?ms)^struct seccomp \{[^}]*\};",
                        "struct seccomp {\n" + fields + "};", header)
assert count == 1, "vmlinux.h must define struct seccomp"

with tempfile.TemporaryDirectory(prefix="shirudo-seal-seccomp-") as directory:
    work = Path(directory)
    (work / "vmlinux.h").write_text(header)
    command = shlex.split(os.environ.get("CLANG", "clang"))
    command += ["-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
                "-Wno-missing-declarations", "-Wno-unused-parameter",
                "-Wdeclaration-after-statement", "-I" + str(work),
                "-I" + str(root / "bpf/lib"),
                "-I" + str(root / "vendor/libbpf"),
                "-I" + str(root / "vendor/libbpf/include/uapi"),
                "-c", str(root / "bpf/seal_verity.c"),
                "-o", str(work / "seal_verity.bpf.o")]
    subprocess.run(command, check=True)
