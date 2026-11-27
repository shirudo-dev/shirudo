# Shape the code

- Functions
- Interfaces
- Resources and errors
- Data and types
- Strings from outside
- State that changes under you
- Warnings, noise and dead code
- Hot paths
- Refactors

Code that reads well is code a mistake cannot hide in. These choices
keep it that way.

## Functions

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

## Interfaces

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

## Resources and errors

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

## Data and types

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

## Strings from outside

`strcmp()`, `strlen()`, `strchr()`, `strrchr()` and their kin read up
to a terminator and take no length. The tree calls them hundreds of
times on strings it terminated itself, so no poison can refuse them as
it refuses `strstr()`, `strcspn()` and the other names
`<shirudo/string.h>` replaces. What
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
entry = strchr(body, '=');
```

write

```c
ret = read_file(path, max, &body, &len);
if (ret)
	return ret;
ret = span_to_str(body, len + 1, body, len);
if (ret)
	goto out;
entry = strchr(body, '=');
```

The `read_unterminated` and `file_as_string` rules of
`testing/coccinelle` report the first of these and a buffer a read left
unterminated; a field, a pointer with a length and a digest are for
review.

## State that changes under you

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

## Warnings, noise and dead code

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

## Hot paths

BPF programs and upatches run in the kernel's hot paths, where these
matter. The userspace commands rarely do.

- Keep the common path straight-line and cheap, and never make it
  slower for a rare case. Move the rare case into a function of its own
  marked `noinline`, keep a critical section minimal, and test before
  writing memory other CPUs read rather than writing it every time.
- Distrust an optimization until it is measured, and remove the ones
  that do not pay.

## Refactors

- Keep a refactor apart from a behavior change, each in a commit of its
  own, and say in the refactor's message that behavior does not change.
- To untangle code, first rewrite it to a clean base, then add each
  special case back as a helper of its own in the next commit.
- A mechanical change, a rename or a converted call, goes in a commit
  of its own.
