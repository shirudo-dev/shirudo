#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Exercise actual native ELF links and the runtime generator's closure checks."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools/gen-image/shirudo-runtime-elf"
loader = importlib.machinery.SourceFileLoader("runtime_elf", str(TOOL))
spec = importlib.util.spec_from_loader(loader.name, loader)
elf = importlib.util.module_from_spec(spec)
loader.exec_module(elf)


class RuntimeELFTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.c = self.root / "probe.c"
        self.c.write_text('#include <stdio.h>\nint main(void) { puts("runtime fixture"); return 0; }\n')
        self.bootstrap = self.root / "bootstrap"
        self.link(self.bootstrap)
        self.layout = elf.closure(self.bootstrap)
        self.flags = shlex.split(elf.run([str(TOOL), "link-flags", "--binary", str(self.bootstrap)]))
        self.runtime = self.root / "runtime"
        self.link(self.runtime, self.flags)

    def link(self, output, flags=()):
        subprocess.run([os.environ.get("CC", "cc"), str(self.c), *flags, "-o", str(output)], check=True)

    def test_direct_entry_has_transitive_fixed_paths_and_distinct_bytes(self):
        elf.validate(self.runtime, self.layout)
        self.assertNotEqual(elf.record(self.bootstrap)["sha256"], elf.record(self.runtime)["sha256"])
        result = elf.stage(self.runtime, self.bootstrap, self.root / "image")
        self.assertEqual(result["files"]["usr/bin/shirudo"], {**elf.record(self.runtime), "mode": 0o755})
        self.assertEqual(result["entry"], "/run/shirudo/runtime/usr/bin/shirudo")
        self.assertEqual(elf.run([str(self.bootstrap)]), "runtime fixture\n")

    def test_normal_loader_and_runpath_and_missing_nodeflib_rejected(self):
        with self.assertRaisesRegex(ValueError, "PT_INTERP"):
            elf.validate(self.bootstrap, self.layout)
        cases = (([f for f in self.flags if f != "-Wl,-z,nodefaultlib"], "NODEFLIB"),
                 ([f.replace("disable-new-dtags", "enable-new-dtags") for f in self.flags], "DT_RPATH"))
        for flags, error in cases:
            self.link(self.runtime, flags)
            with self.assertRaisesRegex(ValueError, error):
                elf.validate(self.runtime, self.layout)

    def test_bad_and_extra_executables_rejected_before_signing(self):
        with self.assertRaisesRegex(ValueError, "PT_INTERP"):
            elf.stage(self.runtime, self.bootstrap, self.root / "image", [self.bootstrap])
        self.assertFalse((self.root / "image").exists())
        for bad in ("/lib/../evil", "/lib//evil", "/lib/with space/evil", "/lib/$ORIGIN/evil"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                elf.safe_path(bad)

    def test_shared_library_search_paths_and_missing_dependency_rejected(self):
        lib = self.root / "libprobe.so"
        src = self.root / "library.c"
        src.write_text('void probe(void) {}\n')
        subprocess.run(["cc", "-shared", "-fPIC", str(src), "-Wl,-soname,libprobe.so",
                        "-Wl,-rpath,/tmp", "-o", str(lib)], check=True)
        flags = ["-Wl,--no-as-needed", "-L" + str(self.root), "-lprobe", "-Wl,-rpath," + str(self.root)]
        self.link(self.bootstrap, flags)
        with self.assertRaisesRegex(ValueError, "own search path"):
            elf.closure(self.bootstrap)
        lib.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            elf.closure(self.bootstrap)

    def test_closure_is_transitive(self):
        src = self.root / "lib.c"
        src.write_text('void child(void) {}\n')
        subprocess.run(["cc", "-shared", "-fPIC", str(src), "-Wl,-soname,libchild.so",
                        "-o", str(self.root / "libchild.so")], check=True)
        src.write_text('extern void child(void); void parent(void) { child(); }\n')
        subprocess.run(["cc", "-shared", "-fPIC", str(src), "-L" + str(self.root), "-lchild",
                        "-Wl,-soname,libparent.so", "-o", str(self.root / "libparent.so")], check=True)
        self.link(self.bootstrap, ["-Wl,--no-as-needed", "-L" + str(self.root), "-lparent",
                                  "-Wl,--disable-new-dtags,-rpath," + str(self.root)])
        layout = elf.closure(self.bootstrap)
        self.assertIn("libchild.so", layout["needed"])
        self.assertIn("libparent.so", layout["needed"])
        flags = shlex.split(elf.run([str(TOOL), "link-flags", "--binary", str(self.bootstrap)]))
        self.link(self.runtime, ["-Wl,--no-as-needed", "-L" + str(self.root), "-lparent",
                                 "-Wl,-rpath-link," + str(self.root), *flags])
        elf.validate(self.runtime, layout)

    def test_bootstrap_loader_ignores_final_runtime_rpath(self):
        evil = self.root / "evil"
        good = self.root / "good"
        evil.mkdir()
        good.mkdir()
        for directory, value in ((evil, 1), (good, 2)):
            source = directory / "lib.c"
            source.write_text(f"int choice(void) {{ return {value}; }}\n")
            subprocess.run(["cc", "-shared", "-fPIC", str(source), "-Wl,-soname,libpick.so",
                            "-o", str(directory / "libpick.so")], check=True)
        source = self.root / "choose.c"
        source.write_text('#include <stdio.h>\nextern int choice(void); '
                          'int main(void) { printf("%d\\n", choice()); return 0; }\n')
        binary = self.root / "choose"
        subprocess.run(["cc", str(source), "-L" + str(evil), "-lpick",
                        "-Wl,--disable-new-dtags,-rpath," + str(evil),
                        "-Wl,-z,nodefaultlib", "-o", str(binary)], check=True)
        loader = self.layout["interpreter"]
        library_path = ":".join([str(good)] + sorted({str(Path(p).parent) for p in self.layout["libraries"]}))
        self.assertEqual(elf.run([loader, "--library-path", library_path, str(binary)]).strip(), "1")
        self.assertEqual(elf.run([loader, "--inhibit-rpath", ":", "--inhibit-cache",
                                  "--library-path", library_path, str(binary)]).strip(), "2")


if __name__ == "__main__":
    unittest.main()
