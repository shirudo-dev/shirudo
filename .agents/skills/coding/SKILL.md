---
name: coding
description: Writes or changes shirudo's C code, userspace or BPF, in the tree's style. Covers the kernel coding style it follows, self-documenting names and shapes, comments, the tree's conventions and poisoned functions, and the checks a change passes; shape.md covers splitting functions, interfaces, resources and errors, types, strings from outside, shared state and hot paths, and util.md the helpers of util/ and include/shirudo/ to use instead of libc or open code. Use whenever writing, changing or reviewing C in shirudo; commit messages follow the commits skill.
paths:
  - "**/*.c"
  - "**/*.h"
---

# Coding

`Documentation/contribute/code/coding-style.rst` is the kernel's coding
style, and the tree follows it in userspace as well as in BPF: tabs
eight wide, 80 columns where it reads well and never past 100, K&R
braces, short functions that do one thing. AGENTS.md points readers to
this skill as the reference for coding conventions; this skill gives them
with their reasons. Read the code around a change first and write like
it, and write what more than one place needs once, in `util/`.

## Write code that explains itself

Write self-documenting code: a reader gets what it does and why from
the names and the shape of the code, without a comment.

- Name a function for what it does and a variable for what it holds:
  `payload_len`, not `n2`; `upatch_name_valid()`, not `check()`; a
  boolean for what is true, `whole`, `found`. A bare number becomes a
  named constant or a `sizeof`.
- A step that would need a comment becomes a small function whose name
  says it, and a condition that needs reading twice becomes a helper or
  a well-named local.
- One function does one job and fits on a screen or two; errors return
  early instead of nesting the rest. "Functions" in shape.md says when
  and where to split one.
- The plain construct beats the clever one. Where the clever one is
  needed for correctness or speed, that need is the why worth a comment.
- A comment that restates the code means the code should change: rename
  or split until the comment says nothing new, then drop it.

Instead of

```c
/* Leave out the per-CPU maps. */
if (type == 5 || type == 6 || type == 10)
	continue;
```

write

```c
if (upatch_map_is_percpu(type))
	continue;
```

## Shape the code

Code that reads well is code a mistake cannot hide in. Read
[shape.md](shape.md) before you write or change a function body, an
interface, a parser of outside bytes or code that shares state: it says
when and where to split a function, how to shape interfaces, resources
and errors, data and types, strings from outside, state that changes
under you, warnings and dead code, hot paths and refactors.

## Use util/, and grow it

Write common code once, in `util/`, and call it. Read
[util.md](util.md) before you write a parser, a check, a path, a copy
loop or a record format, or reach for a libc function the tree poisons:
it gives the helper for each need and when code moves into `util/`.

## Where a file goes

A reader finds code by where it lives, so the tree has to stay easy to
navigate. A new file goes where the tree already keeps its kind:

- A command is `builtin-<command>.c` beside `shirudo.c`, its `cmd_*()`
  declared in `builtin.h`.
- Code two places need is `util/<m>.c` with `util/<m>.h` and its unit
  suite `testing/unit/<m>.c`; the project's basics go in
  `include/shirudo/`.
- The BPF shirudo loads itself is in `bpf/`, and what its programs
  share in `bpf/lib/`. A upatch is a package under `upatches/<name>/`.
- A program of its own is `tools/<tool>/`, or a single script
  `tools/<tool>`. Operator-only code stays out of the core binary: the
  package builder in `tools/shirudo-build/`, signing in `util/sign.c`,
  which only `shirudo-build` links.
- A test goes in its tier and family under `testing/`, CI shell in
  `.github/scripts/`, a page in its section of `Documentation/`.
- Nothing goes at the top level unless it concerns the project as a
  whole, and no README, plan or notes file goes beside the code but the
  ones AGENTS.md excepts, a upatch package's `README.md` among them.

Name a file for what it holds, as its neighbors are named, and give it
one job: a file that grows a second one is split, and the second goes
where its kind lives. A new directory is a structural decision taken
only when no existing one fits; the commit that adds it says why, and
moves nothing else along the way.

## Comments

Code says what it does; a comment is for what it cannot say.

- A `.c` file starts with `// SPDX-License-Identifier: BSD-2-Clause`, a
  header with `/* SPDX-License-Identifier: BSD-2-Clause */`, followed by
  the copyright, `Copyright (c) 2026 Authors of shirudo`, and at most
  five lines on what the file holds. Nothing more at the top.
- In a function, almost never. Write one only for the why a reader
  cannot get from the code: an invariant kept elsewhere, a locking rule
  or an order two steps must keep, a kernel or library quirk ("zlib
  1.3.2 reads past the end of a member"), the reason the obvious way is
  wrong here. Before the code it explains, as short as it can be
  without cutting the reasoning: usually a sentence or two, and what a
  lock or a race needs to be understood, however many that takes.
- Never what the code does, what a name already says, or what a message
  prints; never history or narration of the change ("added for",
  "was", "used by", "fix for", "new helper to"), which goes in the
  commit message; never code commented out.
- Drop a comment that carries nothing only in the lines the change adds
  or touches. Leave the comments of code the change does not touch
  alone, even where you would write them shorter.
- A function's contract goes above its declaration in the header, and
  only when the prototype does not tell it: what it returns on which
  failure, what it owns or frees, what it refuses.
- Where a reader once misread code that was right, a comment goes
  exactly there, and names any other code that must stay in step with
  it.
- Block comments open with `/*` and close with `*/` on lines of their
  own, every line between starting with ` *`; `//` is for SPDX alone.

Clutter, to leave out:

```c
/* Check the length. */
if (len > max)
	return -E2BIG;
```

Worth writing:

```c
/*
 * The header is not signed: .rodata is where the signed loader takes
 * it from, and a header naming another offset would aim the rewrite at
 * other bytes.
 */
```

## Conventions

- Plain C; zero-initialize with `= {}`.
- Integers are `__u8` to `__u64` and `__s8` to `__s64`; `__u64` prints
  with `%llu`, and `ptr_to_u64()` gives the `__u64` the bpf() ABI takes.
  A library interface that takes another type keeps it, and BPF spells
  hook arguments as the kernel's prototypes do. `check-style.sh` refuses
  `uint32_t` and its kin, and in userspace `unsigned int`, `long` and
  the like. System headers that use `uint8_t` and kin go above the first
  shirudo header, which poisons them.
- `strtoul()`, `atoi()`, `sscanf()`, `strcpy()`, `sprintf()`,
  `snprintf()`, `strncmp()`, `strncasecmp()`, `strcasecmp()`,
  `strcspn()`, `strstr()`, `strtok_r()`, `strtok()`, `strsep()`, the
  libc allocators and `explicit_bzero()` are poisoned;
  the table in util.md has what replaces each, and a missing one is wrapped
  in `util/`, never given an exception. So are the string functions of
  libc that nothing calls, `strspn()`, `strpbrk()`, `strcoll()`,
  `strxfrm()`, `strcasestr()`, `strchrnul()`, `strverscmp()`,
  `stpcpy()`, `strlcat()`, `memccpy()`, `bcmp()`, `bcopy()`, `bzero()`,
  `rindex()`, `rawmemchr()`, `gets()`, `strdupa()` and their kin: the
  `#pragma GCC poison` lines of `<shirudo/string.h>` are the list, and
  one comes off it with the first caller that needs it.
- Functions the tree does not use: `rand()`, `srand()`, `random()` and
  their kin (use `getrandom()` for secrets), `gets()`, `tmpnam()`,
  `tempnam()` and `mktemp()` (unsafe by design), `vfork()`, `alloca()`,
  `setjmp()`, `longjmp()`, `sigsetjmp()` and `siglongjmp()` (defeat
  compiler checks), `usleep()` and `signal()` (obsolete; use
  `nanosleep()` and `sigaction()`), `asctime()`, `ctime()`, `gmtime()`,
  `localtime()`, `getpwnam()`, `getpwuid()`, `getgrnam()`, `getgrgid()`,
  `getlogin()` and `ttyname()` (hidden state; use `_r` forms), `index()`
  and `getwd()` (obsolete), and `abort()` and `assert()` (only in tests).
  `testing/coccinelle/banned.cocci` refuses them.
- A `strsprintf()` that does not fit leaves the buffer empty and a
  `strscpy()` leaves a cut copy: either way a path or value is refused,
  a helper formatting display text returns the error, and status shows
  `"?"`. Constant text is copied, not formatted, and a literal copied
  into an array takes `strscpy_literal()`, which fails at build time when
  the literal is too large, not at run time on a path nobody tests.
- `xstrdup()` copies a string and `xstrndup(s, n)` at most its first
  `n` bytes: a prefix, or a bounded copy of what already is a string.
  Both end the copy at a NUL and say nothing, which is wrong for bytes
  that come with a length: those become a string through
  `span_to_str()`, into `len + 1` bytes from `xmalloc()`, which refuses
  the NUL. `xfree(p, size)` and `xstrfree()` scrub before they free.
- `min_t()` and `max_t()` cast and can cut a value, so they are for
  only what `min()` and `max()` refuse; a constant compared with an
  unsigned value takes a `U` suffix.
- `ret` holds a return code, `err` an errno kept beside the value a
  function returns. No `(void)` casts: a result that must be checked
  comes from a `__must_check` function, and every call checks it; a
  result callers may ignore needs none; every build takes
  `-Wno-unused-parameter`, so unused parameters need no cast; an unused
  variable goes. The type check of `min()` and `max()` is the exception.
- Internal names carry no `shirudo_` prefix; it stays only where a name
  leaves the code: include guards, BPF object and pin names, environment
  variables, a clash with libc.
- Locals in reverse-Christmas-tree order, longest line first, except
  where an initializer needs an earlier local.
- Never two blank lines in a row. Removing code often brings the blank
  lines around it together: drop one of them. checkpatch checks only
  the lines a patch adds, so it does not see a pair a deletion makes.
- A frame past 128 KiB fails the build: tables go on the heap, and a
  helper with a big buffer is `noinline_for_stack`.
- Scrub a key, a seed, a credential or a buffer that held one with
  `memzero_explicit()` on every path out, error paths included, and
  compare it with `memneq_explicit()`. Mark a struct member that holds
  one `__sensitive`: a check then wants every local of that struct
  scrubbed the same way, member filled by a parser and all.
- All JSON goes through `util/json.c`; text from outside is written
  with its lossy writers. All logging goes through `pr_*()` to syslog;
  shirudo writes no log file of its own.
- Multi-byte integers in formats and network protocols use the
  little-endian and big-endian types `__le16`, `__le32`, `__le64`,
  `__be16`, `__be32`, `__be64` from `<shirudo/types.h>`, converted to
  and from host order with `cpu_to_le32()`, `le32_to_cpu()`, `get_le32()`,
  `put_be32()` and their kin from `<shirudo/byteorder.h>`. Sparse checks
  that a value is converted before it crosses between host order and these
  types.
- Userspace is BSD-2-Clause. Every file a BPF object compiles, and each
  Lua decoder, is `GPL-2.0 OR BSD-2-Clause`, with
  `char _license[] SEC("license") = "Dual BSD/GPL";`. No emojis.
- BPF code is CO-RE, built for `-mcpu=v4`; upatch code follows the
  `upatch` and `bpf-concurrency` skills.

## Commit messages

Load the `commits` skill before you write the commit message.

## Check

A warning fails the build, so fix it rather than silence it. Build with
GCC and with clang 23 (`make -B` when switching), run the unit suite of
every `util/` file the change touches, adapt and run the proofs under
`testing/proofs/` that reach the code (the `proofs` skill), and run the
`pre-submit` skill's checks before handing the change over: checkpatch
in strict mode, Coccinelle, sparse and both sanitizers find what review
misses.
