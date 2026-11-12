// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A local that a function filled with a secret is scrubbed with
// a full-size memzero_explicit() on every path out of the function, the
// error paths included: what the stack keeps is the next call's to read,
// and a core dump's. The producers are those of the tree whose output is
// secret, an
// activated credential, a KDF output and an ECDH shared value, and
// hex_bytes(), hex_decode() and getrandom() when the local is named for
// a secret. A secret in a struct is sensitive_scrub's.

virtual report

@initialize:python@
@@
import re

SECRET_NAME = re.compile(r"cred|secret|seed|auth|passw|priv")

def unscrubbed(x, p1, p2):
    # The tests hold the throwaway secrets of a test VM.
    if not p2[0].file.startswith("testing/"):
        coccilib.report.print_report(p2[0], "returns without memzero_explicit() of %s, which line %s filled with a secret" % (x, p1[0].line))

@r exists@
identifier x, fld;
type T;
expression C, E, E1;
position p1, p2;
@@
(
  T x[C];
|
  T x;
)
... when any
(
  tpm_activate_credential@p1(..., \(x\|&x\|x.fld\|&x.fld\), E, E1)
|
  tpm_kdfa@p1(..., \(x\|&x\|x.fld\|&x.fld\), E)
|
  tpm_kdfe@p1(..., \(x\|&x\|x.fld\|&x.fld\))
|
  ecdh_p256_ephemeral@p1(..., \(x\|&x\|x.fld\|&x.fld\))
)
... when != memzero_explicit(x, sizeof(x))
    when != memzero_explicit(&x, sizeof(x))
    when != memzero_explicit(x.fld, sizeof(x.fld))
    when != memzero_explicit(&x.fld, sizeof(x.fld))
return@p2 ...;

@n exists@
identifier x;
type T;
expression C, E;
position p1, p2;
@@
(
  T x[C];
|
  T x;
)
... when any
(
  hex_bytes@p1(E, \(x\|&x\), ...)
|
  hex_decode@p1(E, \(x\|&x\), ...)
|
  getrandom@p1(\(x\|&x\), ...)
)
... when != memzero_explicit(x, sizeof(x))
    when != memzero_explicit(&x, sizeof(x))
return@p2 ...;

@script:python depends on report@
x << r.x;
p1 << r.p1;
p2 << r.p2;
@@
unscrubbed(x, p1, p2)

@script:python depends on report@
x << n.x;
p1 << n.p1;
p2 << n.p2;
@@
if SECRET_NAME.search(x):
    unscrubbed(x, p1, p2)

