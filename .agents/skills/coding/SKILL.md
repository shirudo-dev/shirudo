---
name: coding
description: Write or change shirudo's code, the Rust of its userspace and the C of its BPF programs, in the tree's style. Covers rustfmt and the kernel coding style the BPF C follows, when and where to split a function that grew too long, how to shape interfaces, resources, errors, types, shared state and hot paths so that a mistake has nowhere to hide, what to delete, where a comment belongs and where it is clutter, the helpers in rust/src/ to use instead of libc or open code, moving code two places need into rust/src/util/, memory, secrets, JSON and logging, unsafe code and the C it calls, the commit message that carries the change, with a chart where one explains it faster, and the checks a change passes. Use whenever writing, changing or reviewing Rust or C in shirudo.
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
  early instead of nesting the rest. "Functions" below says when and
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

Code that reads well is code a mistake cannot hide in. These choices
keep it that way.

### Functions

How long a function may be depends on how hard it is to follow: the
more it branches and nests, the shorter it has to be. A flat `switch`
that does one small thing per case may run long; a function that keeps
several things in flight may not.

Split a function when any of these holds:

- it runs past two screens, about 50 lines;
- it keeps more than 7 to 10 locals alive at once, more than a reader
  can track;
- its body nests more than three levels deep;
- a block in it needs a comment to say what it does, or comments mark
  where one phase ends and the next begins.

Cut it where the work already divides:

- By phase: read and parse, check, then act, each a function the top
  level calls in turn, so that the top level reads as the list of
  steps.
- A loop body that does more than a few lines becomes a function on one
  item, and the loop stays where it was.
- Each case of a `switch` that does more than a line or two becomes a
  handler of its own.
- Around a resource, the wrapper takes and releases it and an inner
  function does the work, as "Resources and errors" shows.

A good cut leaves each helper a name that says its job and a handful of
parameters. A helper that needs six or more, or that takes most of its
caller's locals, cuts in the wrong place: put the state the steps share
in a struct they take, or cut elsewhere. A helper with one caller is
fine and often right, and one private to its file, `static` in C, lets
the compiler inline it. Do not split a flat `switch` or a table only to
make it shorter, and do not spread one step over two functions.

A split is a refactor: one function per commit, a message that says
behavior does not change and how to read the diff (`git show
--color-moved`). A CBMC harness bounds a loop by its function's name
(`--unwindset <function>.<n>:<bound>` in `proofs.list`), so the
harnesses that include the file follow in the same commit, and the
proofs that reach the code run again. Split the functions a change
writes or touches; a long function the change leaves alone is split in
a series of its own, not along the way.

### Interfaces

- When callers keep getting an interface wrong, change the interface,
  not each caller. Return what every caller needs, such as the end
  pointer rather than a length, or the object found under the lock
  rather than a yes and a second lookup. Make the cleanup accept what a
  failed constructor returns, so that freeing whatever came back is
  always right. Prefer one entry point to two that each have their own
  problem cases.
- Put a check where it cannot be skipped: in the constructor, in the
  one accessor of a raw field, in the single decoder. Fix the helper
  that owns a rule rather than every caller of it.
- Make a special case impossible rather than handled. A counter that
  cannot wrap is a `__u64`; an empty table beats a NULL to test.
- A name means one thing and states an odd contract, even when that
  makes it long. When a field's meaning changes, rename it so that every
  stale user fails to compile, and delete a function whose tempting name
  invites misuse.

### Resources and errors

- Take and release a resource in the same function. When the cleanup
  grows, a wrapper takes and releases and an inner function does the
  work with plain returns, instead of a ladder of `goto` labels:

  ```c
  int record_load(const char *path, struct record *out)
  {
  	int fd, ret;

  	fd = open(path, O_RDONLY | O_CLOEXEC);
  	if (fd < 0)
  		return -errno;
  	ret = record_read(fd, out);
  	close(fd);
  	return ret;
  }
  ```

  In Rust, a type that releases what it holds when it is dropped, an
  `OwnedFd` for a descriptor, releases it on every return.

- Free in the function that allocated. A helper makes all of its
  allocations or none, and hands over ownership by clearing the pointer
  it gave away.
- Order a function so that everything that can fail comes before
  anything that cannot be undone. Compute into a local, check it, then
  publish it to shared state or to an output parameter, and write an
  output once. Check a failure where it happens, so that the shared
  cleanup at the end runs unconditionally.
- One errno for each distinct failure, the one that means it: `ENOTTY`
  for an unknown request, `EAGAIN` for a busy resource, `ENOMEM` only
  for memory.

### Data and types

- The simplest representation that fits: a `__u64`, not two `__u32`; a
  `bool` or a bit, not a bitmap, for two flags; a lookup table, not a
  `switch`, to classify characters; a table indexed by its enum with
  designated initializers, `[KIND_LOAD] = "load"`, not one that depends
  on the order of its lines; no negative enumerator as a sentinel.
- Let the compiler see the real types: `const` on what a function only
  reads, a union instead of a cast, one named helper for a cast that
  cannot be avoided, a constant of the type it is compared with.
- Keep a length in the type it arrives in and make wraparound explicit.
  Compare bytes as `u8`, `unsigned char` in C, or with `memcmp()`; never
  rely on `char`, or Rust's `c_char`, being signed, which it is not on
  arm64 and riscv64.
- Compute in the data's own unit and convert only at the edges. A range
  check subtracts from the limit, where adding to the offset can wrap,
  and accepts an end exactly at the limit:

  ```c
  if (off > size || len > size - off)
  	return -EINVAL;
  ```

  A limit gets a name, not a literal whose digits a reader counts.
- A loop ends by construction: its condition tests what is left, a
  chain it walks must strictly advance, and a limit is clamped once
  before it starts.
- A constant table inside a function is `static const`, or the compiler
  copies it to the stack, which a BPF program has 512 bytes of. A return
  value beats an output parameter wherever one value comes back.

### Strings from outside

`strcmp()`, `strlen()`, `strchr()`, `strstr()`, `strcspn()` and their
kin read up to a terminator and take no length. The tree calls them
hundreds of times on strings it terminated itself, so no poison can
refuse them as it refuses the names `<shirudo/string.h>` replaces. What
makes one of these calls right is where its argument came from, and
nothing checks that but you.

Bytes from outside come with a length: a registry's or a collector's
reply, a token server's answer, a package and its members, an index or
a tree publication, a `.upatch` file and its sections, the settings
and labels of a config image, evidence, the eventlog and the other
sealed logs, a TPM, netlink or ioctl reply, an xattr value, `/proc`
and sysfs text, the kernel's config. A NUL among them ends a string
short of the bytes that were read, hashed or signed, so that two
readers take one input differently: `status` listed the eventlog up to
a NUL where the replay refused the whole log, and the registry client
took a token from the first bytes of an answer that was no text.

- Bytes become a C string only after a check for embedded NUL and a
  terminator is added. `io::read()` and `read_whole()` return owned
  bytes; a caller that needs a C string checks and terminates them.
  Source settings use `BufRead::read_until()` with an explicit length
  and NUL check. JSON strings are decoded before a caller uses them.
- A buffer `read()`, `pread()`, `recv()`, `readlink()` or `getxattr()`
  filled has no terminator until the code writes one.
- A fixed-size field of a format is a string only once its parser found
  a NUL inside it, `memchr(field, '\0', sizeof(field))`, as
  `parse_header()` of `util/upatch.c` does before anything reads the
  name. Two such fields are compared whole, with `memcmp()` over their
  size, as the signed name is with the header's.
- A pointer with a length stays one where it can: `memchr()`,
  `memcmp()`, `span_equals()`, `name_has_suffix()`, `digits()` and
  `parse_u64()` read no further than they are told. Copy it out only
  for a callee that needs a terminator.
- A log of records is walked by the length of its lines, or refused
  whole for a NUL, and a last line without its newline is no record
  (`lines_len()`).
- A name from outside is checked once, by the function that owns its
  rule (`upatch_name_valid()`, `bpm_name_ok()`, `dns_name_valid()`),
  before it reaches a path, a digest or a strict JSON writer; until
  then it is printed through `text_sanitize()` or a lossy writer.
- A digest over several strings delimits or counts each: a tag with its
  NUL, then the fixed-size fields, then at most one field of any length,
  as `chain_upatch_event()` hashes, or one canonical document, as
  `tree_operation_digest()` does. Two strings set side by side hash
  like one string cut elsewhere.

A whole-file read returns bytes. Search them as bytes:

```rust
let body = io::read(path, max)?;
let found = body.split(|&b| b == b'\n').any(|line| line == needle);
```

When a C API needs a string, `CString::new(body)` checks for an embedded
NUL and adds the terminator. The `read_unterminated` and
`file_as_string` Coccinelle rules still catch C buffers used as strings
before that check. A fixed-size field, a pointer with a length and a
digest still need review.

### State that changes under you

- Read a value that can change under you once, into a local, and use
  only the local. In BPF that is `READ_ONCE()`; `volatile` is never the
  fix.
- Never measure and then fill, or test and then look up again, across a
  window in which the data can change. Size for the maximum once, or
  have the lookup return what it found.
- Take the lock a whole operation needs, once. Do not release and retake
  it when the caller holds on to state, re-read what may have changed
  after any lock was dropped, and register for a wakeup before testing
  the condition it waits for.

### Warnings, noise and dead code

- A warning about code a reader also finds hard to follow is fixed by
  making the code clear: return the match from inside the search loop
  rather than break and test the index afterwards. Never a cast, an
  annotation or a dummy value whose only job is to quiet a tool. Where
  no clearer shape exists, start the value at the one the code relies
  on.
- Before adding an annotation or a check that warns, a `#[must_use]`, a
  lint, a Coccinelle rule or an analyzer, fix its existing users in the
  commits before it.
- Print nothing nobody will act on. A warning users cannot respond to
  teaches them that warnings are normal, and then they miss the real
  one.
- Delete rather than keep: a helper with no caller, a variant that is
  dangerous or unused, a debug check that never caught anything, an
  optimization nobody measured to pay off. Disallow what has no reason
  to be allowed; it can come back the day a user needs it.
- No option in place of a decision. A new option defaults off, and
  behavior users rely on, command output, JSON keys and exit statuses,
  is an interface: changing it breaks them.

### Hot paths

BPF programs and upatches run in the kernel's hot paths, where these
matter. The userspace commands rarely do.

- Keep the common path straight-line and cheap, and never make it
  slower for a rare case. Move the rare case into a function of its own
  marked `noinline`, keep a critical section minimal, and test before
  writing memory other CPUs read rather than writing it every time.
- Distrust an optimization until it is measured, and remove the ones
  that do not pay.

### Refactors

- Keep a refactor apart from a behavior change, each in a commit of its
  own, and say in the refactor's message that behavior does not change.
- To untangle code, first rewrite it to a clean base, then add each
  special case back as a helper of its own in the next commit.
- A mechanical change, a rename or a converted call, goes in a commit
  of its own.

## Comments

Code says what it does; a comment is for what it cannot say.

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

## Use rust/src/util/, and grow it

Write common code once, in `rust/src/util/`, and call it. A hash, an
encoding, a digest's text form, a path, a record format, a file read
with its checks, the parse of a name or a number: code that does a job
like these belongs in a module of `rust/src/util/`, or in
`rust/src/text.rs` for the string and number basics, not inline in a
command or a tool. Write it there from the start when a second caller
is in sight, rather than waiting for the copy. Copies drift apart, and
the difference between them is usually a bug in one: the `sha256:`
digest of a manifest was checked and decoded by hand in six places, one
with a length check the others lacked, and written in ten, each its own
way, until `decode_sha256_digest()` and `sha256_digest_encode()`, now
of `rust/src/util/hex.rs`, took the place of them all.

Never write the same logic twice. Before writing a parser, a check, a
path, a copy loop or a record format, look for one that already does it,
in `rust/src/util/`, `rust/src/text.rs` and the commands alike: `git grep
-n '<word>'`. A variant that differs only in a length check, a bound or a
message is still a copy: make one helper, with a parameter or with the
extra check left to the caller, and move one found in a command into
`rust/src/util/` for both. A copy found while working on something else
is consolidated in a commit of its own, before the change that needed
it. A review asks of every new block of code whether `rust/src/util/`
has it already, or should. The basics:

| Need | Use |
|---|---|
| Parse a number | `parse_u64()`, `parse_s64()`, `parse_x64()`, `digits()` (`rust/src/text.rs`) |
| Copy a string into a fixed buffer | `strscpy()`, and check `-E2BIG`; `strsprintf()` to join parts, `csprintf!` for a C format (`rust/src/text.rs`) |
| An upatch's pin directory or a pin in it | `pin_path()` (`rust/src/util/upatch_resolve.rs`) |
| A string's prefix, or a span that must be one literal | `starts_with()` to test a prefix, `strip_prefix()` to step past it, `==` for a span; never a length counted by hand |
| A file name's extension | `name_has_suffix()` (`rust/src/text.rs`), and `dir_names()` (`rust/src/util/io.rs`) with it for the files of a directory that have one |
| Text from outside on a terminal | `sanitize()`; UTF-8 with `utf8_width()` (`rust/src/text.rs`); `rust/src/log.rs` escapes what it logs |
| Sizes and lengths | `checked_add()`, `checked_mul()` and kin, `div_ceil()` |
| Memory | `Vec` and `Box`, from the scrubbing global allocator of `rust/src/heap.rs`; wrap a buffer returned by a C library in an owning type with `Drop` |
| Secrets | `explicit_bzero()` (`rust/src/sys/libc.rs`), `memneq_explicit()` (`rust/src/util/chain.rs`) |
| Files | `read()`, `read_whole()`, `write_complete()`, `append_line()`, `dir_names()`, `dir_names_at()`, `open_beneath()`, `lock_exclusive()` (`rust/src/util/io.rs`) |
| Sealed state and paths root names | `open()`, `open_read()`, `open_sealed()`, `lock()`, `append()`, `mkdir_p()`, `write_file()`; `Output::create()` and `Output::commit()` for a report or export, `output_open()` for one appended to (`rust/src/util/seal.rs`) |
| Bytes on the wire | `from_le_bytes()`, `to_be_bytes()` and kin; `encode()`, `decode()` and `decode_max()` for hex (`rust/src/util/hex.rs`) |
| SHA-256 | `sha256()` or `sha256_into()` of a slice, or a `Sha256Ctx` through `sha256_init()`, `sha256_update()` and `sha256_final()` over pieces (`rust/src/util/crypto_openssl.rs`); `sha256_digest_encode()` and `decode_sha256_digest()` for the `sha256:<hex>` form (`rust/src/util/hex.rs`), `sha256_hex()` for its bare hex (`rust/src/util/bpm_oci/http.rs`) |
| JSON | `rust/src/util/json/`: `parse_schema()` over a table of `JsonField`s into a state the caller passes, each field naming its place in it, and `JsonEmit`, whose `str_lossy()` and `key_lossy()` write text from outside |
| Messages | `log::err()`, `warn()`, `info()`, `audit()`, and `log_c!` for a C format (`rust/src/log.rs`) |
| A command's options | a table of `OptSpec` indexed by the command's constant for each option, an `OptParser` and a `match` over its `next()`, `number()` for a value in a range, `choice()` for one from a set of `OptName`s, `usage()` and `EXIT_USAGE` (`rust/src/util/options.rs`); `HelpSection::options()` (`rust/src/util/help.rs`) lists the same table in help, and `--list-opts` for completion; never compare an argument by hand |

Code that a second place needs moves into `rust/src/util/<m>.rs`, or
into `rust/src/text.rs` for the string and number basics, with cases in
its `tests.rs`, and the copies it replaces go in the same commit, whose
message names each copy and how they differed. Two private copies of
one helper in two commands are a bug in waiting: one gets fixed and the
other does not. A util function takes a slice rather than trusting a
terminator in outside data, returns 0 or a negative errno, or a
`Result` whose error is one, and leaves the message to its caller.

Code the BPF programs share goes in `bpf/lib/` the same way. Where a
shared helper does not make sense, the copy stays and its commit says
why: operator-only code, signing and the package builder, stays out of
the core binary, and a file a CBMC proof includes whole keeps a local
copy when a call into another file would leave the proof a function
without a body.

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

`Documentation/contribute/code/contributing.rst` sets the form: the
subject `area: imperative summary`, specific ("seal: refuse the
runtime to a task that shares its file system context", not "seal:
fixes") and at most 75 characters; the body wrapped at 75 columns, the
problem and its impact before the change. Write it for a reviewer who
reads it once:

- Short, plain sentences, one idea each. No filler and no long
  background; drop any sentence the reviewer does not need to
  understand the problem or the fix.
- Plain paragraphs for a simple bug. `[BUG]`, `[CAUSE]` and `[FIX]`
  headings only where the symptom, the cause and the fix each take
  several paragraphs.
- Quote what a program printed, an error, a log line or a call trace,
  as it printed it: quoted text has no column limit and is never
  folded.
- Read `git log -- <the files>` for the recent messages of the area
  before writing one.
- Where a chart explains the problem faster than prose, draw one.
- The length follows the reasoning, not the diff: a one-line fix can
  need three paragraphs, and deleting dead code one sentence.
- When old code changes or goes, say why it once made sense and why
  that reason is gone, citing the commits that added it and that broke
  it.
- State the scope: what the change deliberately leaves alone, whether
  it is the minimal fix and what the full one would be and why it waits,
  what was tested and what was not, and what would make it be undone.
- Where a bug has a short reproducer, give it: the command or the small
  program, and what it printed.
- Where an interface changes, show the old and the new call in a short
  snippet.
- A mechanical change gives the exact command that made it, `git grep
  -l ... | xargs sed -i ...`, says how to review it, for instance with
  `git show -w`, and lists the cases fixed by hand.
- A revert has the subject `Revert "<subject>"` and starts with `This
  reverts commit <hash> ("<subject>").`, then gives the symptom as
  reported, why it is reverted rather than fixed now, and what comes
  next. A partial revert says what it keeps.
- A side note, such as advice for a backport or a nit outside the
  change, goes in a `[ ... ]` paragraph after the main text.

### Charts

An ASCII chart earns its place for:

- a race: show the window, side by side, rather than describe it;
- an error path seen from several callers, where one cleans up what
  another already did;
- a call chain across layers where the bug shows on one path only;
- the order of steps, as in a load's pins, archive and extend, or
  `init`'s phases.

Function names only, no file paths or line numbers, and only the
functions that matter. A state or an outcome goes in plain words under
the function name. A race takes one column per racing context: a
command, root, a CPU, a kworker.

A race, a load that root stops between its pins and its extend:

```
 shirudo upatch load                root
 upatch_load()
 |-upatch_apply()
 | \-attach_and_pin_progs()
 |   The links are attached
 |                                  kill -9 <pid>
 |                                  The load ends here
 \-upatch_chain_event_locked()
   Never runs: pins without a record in the register.
```

A call chain where the bug shows on one path, an exec that fails past
its point of no return:

```
 load_elf_binary()
 |-begin_new_exec()
 | \-security_bprm_committed_creds()
 |   The task now holds runtime authority
 |
 \-create_elf_tables()
   Fails: SIGSEGV, and the core dump runs as the task
   \-coredump_file()
     Unlinks the core_pattern path with that authority.
```

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

These rules apply only to C maintained by Shirudo: BPF programs,
remaining userspace helpers, and C test or build helpers. They do not
apply to Rust or vendored sources.

The remaining C helpers under `util/` and `tools/shirudo-build/` keep
the kernel C style above. Keep their headers, tests, and C callers in
sync when changing an interface. Check the return from `strscpy()` and
`strsprintf()`, release allocations on every error path, and use the
existing zeroing helpers for secrets. New shared userspace logic belongs
in Rust.

### Coccinelle and sparse

- `testing/coccinelle/banned.cocci` reports C calls to functions Shirudo
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
`__le32`, `__le64`, `__be16`, `__be32`, and `__be64` types and convert
between host and wire order with `include/shirudo/byteorder.h`. `make
sparse` checks these conversions in maintained C sources; it leaves
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
