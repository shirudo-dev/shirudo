---
name: coding
description: Writes or changes shirudo's Rust userspace and BPF C in the tree's style. Covers naming, comments, conventions and checks; shape.md covers functions, interfaces, resources, outside data and hot paths, and util.md lists shared Rust helpers. Use for Rust or C changes; commit messages follow the commits skill.
paths:
  - "**/*.rs"
  - "**/*.c"
  - "**/*.h"
---

# Coding

Most of shirudo's userspace is Rust, the `shirudo` crate under
`rust/`, laid out by `rustfmt`. Its BPF programs and remaining C test
and build helpers follow the kernel's coding style,
`Documentation/contribute/code/coding-style.rst`: tabs eight wide,
80 columns where it reads well and never past 100, K&R braces, short
functions that do one thing. AGENTS.md points to this skill as the
reference for coding conventions; the skill gives them with their
reasons. Read the code around a change first and write like it, and
write shared Rust logic in `rust/src/util/` and shared BPF code in
`bpf/lib/`.

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
  early instead of nesting the rest. "Functions" in shape.md says when and
  where to split one.
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

Read [shape.md](shape.md) before changing a function body, an
interface, a parser of outside bytes, or code that shares state. It
covers functions, resources, errors, types, bounds and hot paths.

## Use rust/src/util/, and grow it

Read [util.md](util.md) before writing a parser, a check, a path, a
copy loop or a record format. It lists the shared Rust helpers and
when code belongs in `rust/src/util/`.

## Where a file goes

A reader finds code by where it lives. Put a new file beside code of
its kind:

- A shirudo command lives in `rust/src/builtin/<command>.rs`, with its
  module registered in `rust/src/builtin/mod.rs`.
- Shared Rust logic lives in `rust/src/util/<module>.rs`, with tests in
  that module's `tests.rs`. String and number basics live in
  `rust/src/text.rs`.
- shirudo's own BPF programs live in `bpf/`, shared BPF code in
  `bpf/lib/`, and an upatch package under `upatches/<name>/`.
- A separate program lives under `tools/<tool>/`, or as one script at
  `tools/<tool>`. The Rust package builder lives in
  `rust/src/shirudo_build/`; operator-only work stays out of the core
  command.
- Tests go in their tier and family under `testing/`, CI scripts in
  `.github/scripts/`, and documentation in its section of
  `Documentation/`.
- Top-level files concern the project as a whole. The README exceptions
  in AGENTS.md still apply.

Name a file for what it holds, as its neighbors are named, and give it
one job: a file that grows a second one is split, and the second goes
where its kind lives. A new directory is a structural decision taken
only when no existing one fits; the commit that adds it says why, and
moves nothing else along the way.

## Comments

Code says what it does; a comment is for what it cannot say. Its prose
follows the `writing` skill.

- A `.rs` or `.c` file starts with `// SPDX-License-Identifier:` and the
  licence of its kind (Conventions below), a header with the same line
  in `/* */`, followed by the copyright, `Copyright (c) 2026 Authors of
  shirudo`, and at most five lines on what the file holds, `//!` lines
  in Rust. Nothing more at the top.
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
- A function's contract goes in the `///` comment above it, above its
  declaration in a C header, and only when the signature does not tell
  it: what it returns on which failure, what it owns or frees, what it
  refuses. An `unsafe fn` says under `# Safety` what its caller must
  make true.
- Where a reader once misread code that was right, a comment goes
  exactly there, and names any other code that must stay in step with
  it.
- In C, block comments open with `/*` and close with `*/` on lines of
  their own, every line between starting with ` *`; `//` is for SPDX
  alone. Rust comments are `//`, with `///` and `//!` for documentation.

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

- C is plain C, zero-initialised with `= {}`.
- In C, integers are `__u8` to `__u64` and `__s8` to `__s64`, from
  `vmlinux.h` in BPF; `__u64` prints with `%llu`. A library interface
  that takes another type keeps it, and BPF spells hook arguments as the
  kernel's prototypes do. `check-style.sh` refuses `uint32_t` and its
  kin.
- A number from outside is parsed with `parse_u64()` and its kin, which
  take a bound and refuse a blank, a base prefix and the leading `+`
  that `str::parse()` takes.
- A `strsprintf()` or `csprintf!` that does not fit leaves the buffer
  empty: a path or value is refused, a helper formatting display text
  returns the error, and status shows `"?"`. Constant text is copied,
  not formatted.
- A C string from outside gets a length bound before `strlen()` or
  another call that searches for its terminator. Counted bytes stay
  counted until a checked conversion makes them a C string.
- In C, `ret` holds a return code and `err` an errno kept beside the
  value a function returns, and there are no `(void)` casts.
- Internal names carry no `shirudo_` prefix; it stays only where a name
  leaves the code: include guards, BPF object and pin names, environment
  variables, the entry points a `main()` object calls, a clash with
  libc.
- In C, locals go in reverse-Christmas-tree order, longest line first,
  except where an initializer needs an earlier local.
- Never two blank lines in a row. Removing code often brings the blank
  lines around it together: drop one of them. checkpatch checks only
  the lines a patch adds, so it does not see a pair a deletion makes.
- Scrub a key, a seed, a credential or a buffer that held one on every
  path out, error paths included, and compare it with
  `memneq_explicit()`. The allocator scrubs what it frees; what it does
  not hand out, a local, a static or a library's buffer, takes
  `explicit_bzero()`, from a `Drop` where a type holds the secret, as
  `Scrubbed` of `rust/src/util/config.rs` does.
- All JSON goes through `rust/src/util/json/`; text from outside is written
  with its lossy writers. All logging goes through `rust/src/log.rs` to syslog;
  shirudo writes no log file of its own.
- Fields of a little- or big-endian format are read and written with
  `from_le_bytes()`, `to_be_bytes()` and their kin.
- Userspace is BSD-2-Clause. Every file a BPF object compiles, and each
  Lua decoder, is `GPL-2.0 OR BSD-2-Clause`, with
  `char _license[] SEC("license") = "Dual BSD/GPL";`. No emojis.
- BPF code is CO-RE, built for `-mcpu=v4`; upatch code follows the
  `upatch` and `bpf-concurrency` skills.

## Commit messages

Load the `commits` skill before you write the commit message.

## Rust

Most userspace is the `shirudo` crate under `rust/`, a static library
every binary links. Much of it keeps the shape of the C it replaced:
raw pointers, `c_int` results and `capi` submodules that hold the
pointer-shaped interface of a C header that is gone. New and changed
code follows the rules below, and the C-shaped code a change touches
is brought to them in the same series: its callers take the safe form
and the C-shaped one goes.

- A safe function takes references, slices, `&CStr`, fixed-size arrays
  and owned types. A raw pointer is for an `unsafe fn` at the edge with
  C, whose `# Safety` says what it must point at, and is made a
  reference or a slice there once, through `rust/src/ffi.rs`; a safe
  function that dereferences a pointer it was given is unsound however
  its callers use it.
- A failure is a `Result`, its error a negative errno, passed on with
  `?`. What a function finds goes in the `Ok`, not through an
  out-parameter beside a status. A bare `c_int` status stays only where
  C calls the function, as a callback of libcurl or LuaJIT does.
- What is acquired is released by `Drop`: a descriptor as an `OwnedFd`
  or a `File`, owned bytes as a `Vec`, a C allocation in a wrapper whose
  `Drop` frees it, and a lock in a guard. A manual `close()` or `free()`
  on a return path risks a leak on another path.
- Nothing from outside panics: data read from a file, the network, the
  kernel or the command line is taken with `get()`, `split_at_checked()`
  and their kin, never indexed past a length the code has not checked,
  and never `unwrap()`ed. `expect()` states only an invariant the code
  itself made, in its message. A panic aborts the command.
- `as` converts only where the value fits by construction, a `u8` into
  a `u32`, a constant into its type. A length, a count or an offset from
  outside goes through `try_from()`, and its error refuses the input.
- No `static mut` of the crate's own; a value set once is a `OnceLock`,
  a counter an atomic, anything else is passed to who needs it.
- `unsafe` covers the one operation that needs it. A foreign function
  the crate calls in more than one place gets a safe wrapper beside its
  declaration, and the callers call that.
- `mem::zeroed()` is for a `#[repr(C)]` type whose C definition takes
  all zeros as a valid value; a Rust type has a constructor or
  `Default`.
- Visibility is as narrow as the callers allow, `pub(super)` before
  `pub(crate)`; `pub` and `#[unsafe(no_mangle)]` are for the entry
  points the `main()` objects, the test helpers and the fuzz targets
  call.

- The commands are `rust/src/builtin/`, one module for each, which the
  table of `rust/src/builtin/commands.rs` dispatches to; what more than
  one place needs is `rust/src/util/`; the operator's builder and
  signer are `rust/src/shirudo_build/`, which only `shirudo-build`
  reaches; the BPF object model and the loaders it generates are
  `rust/src/bpf/`. The test helpers are `rust/src/helpers/`, built
  only with the `test-helpers` feature, and a module's fuzz entry
  points are its `fuzz.rs`, built only under `cfg(shirudo_fuzz)`. A
  binary's `main()` is a `no_std` object of its own, `shirudo.rs`,
  `tools/shirudo-build/shirudo-build.rs`,
  `tools/quote-check/quote-check.rs` or one made from
  `testing/helper/main.rs.in`, which hands the command line to the
  crate, so that the tests can link the crate with a `main()` of their
  own.
- An errno is a constant of `rust/src/errno.rs`, negative wherever a
  function hands it back.
- `rust/src/ffi.rs` turns what C hands over into Rust views: `c_str()`
  for a C string, `slice()` for an array that may be NULL when empty,
  `bytes_mut()` for a C buffer to write into as it is, and `c_splice!`
  for a C string spliced from constants at compile time.
  `rust/src/text.rs` gives Rust code the string rules of the C library
  over byte slices, `cstr()` for the string a buffer holds, `strscpy()`
  to `parse_u64()`.
- What std does not cover is declared in `rust/src/sys/`: the C library
  through the `libc` crate, with the few glibc symbols the crate does
  not bind, libcurl, LuaJIT, tpm2-tss through `tss-esapi-sys`, and the
  OpenSSL calls that neither the `openssl` crate nor `openssl-sys`
  covers.
- Every `unsafe` block says in a `// SAFETY:` comment what part of the
  contract of what it calls makes it sound, and an `unsafe fn` says
  under `# Safety` what its caller must make true. `rust/Cargo.toml`
  denies `unsafe_op_in_unsafe_fn`, so that an unsafe operation takes a
  block of its own inside an `unsafe fn` too, and clippy's
  `undocumented_unsafe_blocks`, so that `cargo clippy` fails on a block
  without its comment.
- std, and a crate only where it replaces a large binding layer and
  AGENTS.md's dependency rules admit it, vendored in `rust/vendor` and
  pinned in `rust/Cargo.lock` so that cargo builds offline.
- Every Rust allocation goes through the global allocator of
  `rust/src/heap.rs`, which hands out zeroed memory and scrubs a block
  before it frees it, the old block of one that grows included. Use
  owned Rust buffers. A buffer returned by a C library belongs to an
  owning wrapper whose `Drop` frees it exactly once.
- A panic is a bug: `rust/src/panic.rs` reports it through `log::err()`
  and aborts. The crate unwinds only so that a Lua error can cross a
  `"C-unwind"` callback, and a Rust frame such an unwind may cross holds
  nothing that must be dropped. Overflow checks and LTO hold in every
  release build, and arithmetic that input can overflow is checked, so
  that the input is refused rather than the command aborted.
- `rustfmt` sets the layout. Comments follow the rules above with `//`
  and `///`, and `//!` holds the lines of purpose under the SPDX line
  and the copyright.

## Remaining userspace C

These rules apply only to C maintained by shirudo: BPF programs,
remaining userspace helpers, and C test or build helpers. They do not
apply to Rust or vendored sources.

The remaining C helpers under `util/` and `tools/shirudo-build/` keep
the kernel C style above. Keep their headers, tests, and C callers in
sync when changing an interface. Check the return from `strscpy()` and
`strsprintf()`, release allocations on every error path, and use the
existing zeroing helpers for secrets. New shared userspace logic belongs
in Rust.

### Coccinelle and sparse

- `testing/coccinelle/banned.cocci` reports C calls to functions shirudo
does not use, including `rand()` and its kin, `strtok()`, temporary-file
functions, `vfork()`, `alloca()`, `setjmp()` and `longjmp()`, obsolete
time and signal functions, user and group database lookups, and
`abort()` or `assert()` outside tests. Use `getrandom()` for secrets,
reentrant (`_r`) forms for hidden state, and `nanosleep()` or
`sigaction()` for obsolete interfaces. Test sources may use functions
they exercise.
- Use `strscpy_literal()` to copy a string literal into a fixed array.
It rejects a literal that does not fit at build time. The
`literal_strscpy.cocci` rule reports a literal passed to `strscpy()`.
- Do not cast an unused parameter to `void`. The build disables
`-Wunused-parameter`; remove unused variables, and check results marked
`__must_check`.
- For multi-byte fields in C formats and protocols, use the `__le16`,
`__le32`, `__le64`, `__be16`, `__be32`, and `__be64` types. Use the
kernel byte-order helpers in BPF code and Rust byte conversion methods
in userspace. `make sparse` checks maintained C sources and leaves
vendored sources out.

## Check

A warning fails the build, rustc's as the C compiler's, so fix it
rather than silence it. Build with GCC and with clang 23 (`make -B` when
switching), run the unit suite of every module the change touches
(`make -C testing unit/<module>`), adapt and run the proofs under
`testing/proofs/` that reach the code (the `proofs` skill), and run the
`pre-submit` skill's checks before handing the change over: `cargo fmt
--check` and `cargo clippy` keep `rust/` to its style and its
`// SAFETY:` comments, checkpatch in strict mode and Coccinelle keep the
C to its, and the sanitizers and the fuzz targets find what review
misses.
