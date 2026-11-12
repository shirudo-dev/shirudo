// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A local of a struct with a field a header marks __sensitive holds a
// secret once the function uses it, and is scrubbed on every path out of
// the function, the error paths included: by memzero_explicit() of the
// whole struct, or by a __cleanup() function that does, as
// config_clear() and bpm_oci_client_clear() do. A compound literal of
// such a struct has no name to scrub. The struct names come from the
// headers under include/, util/ and tools/ and at the top of the tree,
// so that marking a field brings its struct under the rule.

virtual report

@initialize:python@
@@
import os
import re

STRUCT = re.compile(r"^struct (\w+) \{")

def sensitive_structs():
    paths = [f for f in os.listdir(".") if f.endswith(".h")]
    for top in ("include", "util", "tools"):
        for root, dirs, files in os.walk(top):
            paths += [os.path.join(root, f) for f in files if f.endswith(".h")]
    found = set()
    for path in paths:
        name = None
        with open(path, errors="replace") as f:
            for line in f:
                m = STRUCT.match(line)
                if m:
                    name = m.group(1)
                elif line.startswith("}"):
                    name = None
                elif name and re.search(r"\b__sensitive\b", line) and \
                     not line.lstrip().startswith(("*", "/*")):
                    found.add(name)
    return found

SENSITIVE = sensitive_structs()
# Run from elsewhere than the top of the tree, the rule would find no
# struct and pass whatever the code does.
if not SENSITIVE:
    raise RuntimeError("sensitive_scrub: no __sensitive field found; run spatch from the top of the tree")

def declared_with_cleanup(p):
    with open(p[0].file, errors="replace") as f:
        for i, line in enumerate(f, 1):
            if i == int(p[0].line):
                return "__cleanup(" in line
    return False

// Keep scrub references out of the use positions below.
@m@
identifier x;
position pm;
@@
memzero_explicit(<+... x@pm ...+>, ...)

@m2@
identifier x;
expression E;
position pm;
@@
memzero_explicit(E, <+... x@pm ...+>)

@r exists@
identifier sname : script:python() { sname in SENSITIVE };
identifier x;
position pd, p1 != {m.pm, m2.pm}, p2;
@@
struct sname@pd x;
... when != x
x@p1
... when != memzero_explicit(&x, sizeof(x))
return@p2 ...;

@c@
identifier sname : script:python() { sname in SENSITIVE };
position p;
@@
  &(struct sname){...}@p

@script:python depends on report@
x << r.x;
pd << r.pd;
p2 << r.p2;
@@
# The tests hold the throwaway secrets of a test VM.
if not p2[0].file.startswith("testing/") and not declared_with_cleanup(pd):
    coccilib.report.print_report(p2[0], "returns without memzero_explicit() of %s, which holds a secret" % x)

@script:python depends on report@
p << c.p;
@@
if not p[0].file.startswith("testing/"):
    coccilib.report.print_report(p[0], "a compound literal holds a secret that nothing scrubs")
