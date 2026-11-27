---
name: coding
description: Write or change shirudo's C code, userspace or BPF, in the tree's style. Covers the kernel coding style it follows, when and where to split a function that grew too long, how to shape interfaces, resources, errors, types, shared state and hot paths so that a mistake has nowhere to hide, what to delete, where a comment belongs and where it is clutter, the helpers in util/ and include/shirudo/ to use instead of libc or open code, moving code two places need into util/, memory, secrets, JSON and logging, and the checks a change passes. Use whenever writing, changing or reviewing C in shirudo; commit messages follow the commits skill.
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
fine and often right, and `static` lets the compiler inline it. Do not
split a flat `switch` or a table only to make it shorter, and do not
spread one step over two functions.

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
  Compare bytes as `unsigned char` or with `memcmp()`; never rely on
  `char` being signed, which it is not on arm64 and riscv64.
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

- Bytes become a string in one step that takes their length, refuses a
  NUL among them and terminates them. `span_to_str()` is that step for
  a file read whole, in place, as `read_file()` leaves room for the
  terminator, for a reply, a counted field and a line cut out of a
  text. `read_text_line()` is it for the lines of a settings file, and
  `json_parse()` and `json_walk()` for a document, whose strings they
  hand out decoded and terminated.
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

Instead of

```c
ret = read_file(path, max, &body, &len);
if (ret)
	return ret;
entry = strstr(body, needle);
```

write

```c
ret = read_file(path, max, &body, &len);
if (ret)
	return ret;
ret = span_to_str(body, len + 1, body, len);
if (ret)
	goto out;
entry = strstr(body, needle);
```

The `read_unterminated` and `file_as_string` rules of
`testing/coccinelle` report the first of these and a buffer a read left
unterminated; a field, a pointer with a length and a digest are for
review.

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
- Before adding an annotation or a check that warns, a `__must_check`, a
  Coccinelle rule or an analyzer, fix its existing users in the commits
  before it.
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

## Use util/, and grow it

Write common code once, in `util/`, and call it. A hash, an encoding, a
digest's text form, a path, a record format, a file read with its
checks, the parse of a name or a number: code that does a job like
these belongs in a helper of `util/`, or of `include/shirudo/` for the
project's basics, not inline in a builtin or a tool. Write it there
from the start when a second caller is in sight, rather than waiting
for the copy. Copies drift apart, and the difference between them is
usually a bug in one: the `sha256:` digest of a manifest was checked
and decoded by hand in six places, one with a length check the others
lacked, and written in ten, each its own way, until
`sha256_digest_decode()` and `sha256_digest_encode()` in `util/hex.c`
took the place of them all.

Never write the same logic twice. Before writing a parser, a check, a
path, a copy loop or a record format, look for one that already does it,
in `util/`, `include/shirudo/` and the builtins alike: `git grep -n
'<word>'`. A variant that differs only in a length check, a bound or a
message is still a copy: make one helper, with a parameter or with the
extra check left to the caller, and move one found in a builtin into
`util/` for both. A copy found while working on something else is
consolidated in a commit of its own, before the change that needed it.
A review asks of every new block of code whether `util/` has it
already, or should. The basics:

| Need | Use |
|---|---|
| Parse a number | `parse_u64()`, `parse_s64()`, `parse_x64()`, `digits()` (`<shirudo/string.h>`) |
| Copy or format a string | `strscpy()`, `strsprintf()`, `vstrsprintf()`, and check `-E2BIG`; `strscpy_literal()` for a string literal into an array, which fails the build where it does not fit (`<shirudo/string.h>`) |
| A upatch's pin directory or a pin in it | `upatch_pin_path()` (`util/paths.h`) |
| A string's prefix, or a span that must be one string | `str_has_prefix()` to test a literal prefix and `str_skip_prefix()` to step past it, `str_after_prefix()` for the rest after a prefix known only at run time, each with a `_nocase` form for a letter in either case; `span_equals()` for a span of known length against a literal, `span_equals_str()` against a string, `span_has_prefix_nocase()` for a span's start; `str_equals_nocase()` for two whole strings in either case (`<shirudo/string.h>`); `strncmp()` and `strncasecmp()`, whose length a caller counts by hand, and `strcasecmp()` are poisoned |
| A byte of a set, or a string, in the bytes you hold | `span_until()` for the length up to the first byte of a set, `span_find()` for where a string lies in a span, `str_contains()` for whether a string holds another (`<shirudo/string.h>`); `strcspn()`, `strpbrk()` and `strstr()`, which search to a terminator, are poisoned |
| The lines of a buffer, the words of a line, the entries of a list | `for_each_token()` (`<shirudo/string.h>`), which gives each token as pointer and length and writes nothing; a caller that needs a terminated token ends it in a buffer of its own; `strtok_r()`, `strtok()` and `strsep()` are poisoned |
| A file name's extension | `name_has_suffix()` (`<shirudo/string.h>`), `upatch_select()` for a scandir of upatches |
| Text from outside on a terminal | `text_sanitize()`; UTF-8 with `utf8_width()` |
| Bytes from outside as a string | `span_to_str()` (`<shirudo/string.h>`), which takes their length and refuses a NUL among them; `read_text_line()` for a line of a settings file (`util/io.h`) |
| Sizes and lengths | `check_add_overflow()` and kin, `size_add()`, `size_mul()`, `struct_size()`, `DIV_ROUND_UP()` (`<shirudo/overflow.h>`) |
| Smaller or larger | `min()`, `max()` (`<shirudo/misc.h>`) |
| Memory | `xmalloc()`, `xcalloc()`, `xreallocarray()`, `xstrndup()`, `xasprintf()`, `xfree(p, size)` (`util/malloc.h`) |
| Secrets | `memzero_explicit()`, `memneq_explicit()` |
| Files | `read_file()`, `read_fd()`, `write_complete()`, `append_line()`, `lines_len()`, `open_beneath()`, `lock_exclusive()` (`util/io.h`); `open_trusted()` to open by name a file under `/etc/shirudo` or `/var/lib/shirudo` that steers what shirudo trusts, never `open()` and `check_trusted()`, and `check_secret()` once such a file turns out to hold a secret |
| Sealed state and paths root names | `seal_open()`, `seal_lock()`, `seal_append_line()`, `seal_write_file()`; `seal_output_create()` and `seal_output_commit()` for a report or export (`util/seal.h`) |
| Bytes on the wire | `get_le32()`, `put_be32()`, `le32_to_cpu()` and kin (`<shirudo/byteorder.h>`), `hex_encode()`, `hex_decode()`, `hex_decode_max()` (`util/hex.h`) |
| SHA-256 | `sha256_buffer()`, or `sha256_init()`, `sha256_update()` and `sha256_final()` over pieces (`util/crypto.h`); `sha256_digest_encode()` and `sha256_digest_decode()` for the `sha256:<hex>` form (`util/hex.h`), `bpm_sha256_digest()` to hash and write it at once (`util/bpm_oci.h`) |
| JSON | `util/json.h`: `json_parse()` with a schema, `json_walk()`, `struct json_emit` |
| Messages | `pr_err()`, `pr_warn()`, `pr_info()`, `pr_audit()` (`util/log.h`) |
| A command's options | a table of `struct opt_spec` indexed by the command's enum, `OPT_INIT()`, a switch over `opt_next()`, `opt_u64()`, `OPT_CHOICE()` for a value from a set of names, `opt_usage()` and `EXIT_USAGE` (`util/options.h`); `HELP_OPTIONS()` lists the same table in help, and `--list-opts` for completion; never compare `argv[]` by hand |

Code that a second place needs moves into `util/<m>.c`, declared in
`util/<m>.h`, or in `include/shirudo/` for the project's basics, with
cases in `testing/unit/<m>.c`, and the copies it replaces go in the same
commit, whose message names each copy and how they differed. Two static
copies of one helper in two builtins are a bug in waiting: one gets
fixed and the other does not. A util function takes a length rather
than trusting a terminator in outside data, returns 0 or a negative
errno, and leaves the message to its caller.

Code the BPF programs share goes in `bpf/lib/` the same way. Where a
shared helper does not make sense, the copy stays and its commit says
why: operator-only code, signing and the package builder, stays out of
the core binary, and a file a CBMC proof includes whole keeps a local
copy when a call into another file would leave the proof a function
without a body.

## Conventions

- Plain C; zero-initialise with `= {}`.
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
  the table above has what replaces each, and a missing one is wrapped
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
