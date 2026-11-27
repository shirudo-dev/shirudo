---
name: unit-tests
description: Writes and changes shirudo's unit tests, the suites of testing/unit/ that call the util/ module of the same name in-process, and the few suites that link an object outside util/ through UNIT_OBJS. Covers the unit.h harness (UNIT_CASE, UNIT_SUITE, the EXPECT and ASSERT macros, unit_skip), the child each case runs in, building and running one suite or one case, fixtures under TMPDIR and in a memfd, link-time --wrap fakes, cases that need root, both compilers and what each sanitizer does and does not see. Use when adding or changing a function in util/, when a unit suite fails, or when touching testing/unit/.
paths:
  - "testing/unit/**"
  - "util/**/*.c"
---

# Unit tests

The unit tier calls the C of `util/` in-process on the build host and
runs in seconds. It reaches no BPF LSM, keyring, TPM or VM. A script, a
command's behavior, enforcement on a target and a delivery path belong
in other tiers: "Choose a tier" in the `testing` skill decides.

`Documentation/contribute/testing/testing.rst` ("Write a unit test",
"Run under the sanitizers", "Run under MemorySanitizer") is the
reference. This skill adds the procedure and the traps.

## A suite

`util/<m>.c` is tested by `testing/unit/<m>.c`. Copy the shape of
`testing/unit/hex.c`, a short suite: the module's header by its
bare name (`"hex.h"`, since `util/` is on the include path), then
`"unit.h"`, one static function per case, the table and
`UNIT_SUITE(<m>, cases);`. A suite's file starts with
`// SPDX-License-Identifier: BSD-2-Clause` and
`/* Copyright (c) 2026 Authors of shirudo */`.

- Name a case for what holds, `decode_wants_the_exact_length`: the
  function name is the TAP title and the substring a run selects.
- List every case in the table, which ends with `{}`. A case left out
  is an unused static function, and `-Werror` fails the build.
- `EXPECT_*` records a failure and goes on, `ASSERT_*` ends the case.
  Use `ASSERT_*` where a later line would dereference what failed.
- `EXPECT_EQ`, `_NE`, `_LT` and `_GT` compare as `__s64`; a `size_t` or
  `__u64` above `INT64_MAX` takes `EXPECT_UEQ` or `ASSERT_UEQ`. There is
  no `ASSERT_LT`: write `ASSERT_TRUE(a < b)`.
- `EXPECT_STREQ` fails on a NULL; `EXPECT_MEMEQ` prints the first byte
  that differs.
- `unit_skip("<reason>")` ends a case as `ok <n> - <case> # SKIP
  <reason>`. Skip only for what the host lacks, never for a result.
- A non-static function in a suite, such as a `__wrap_` fake, needs a
  prototype first or `-Wmissing-prototypes` fails the build: declare it
  above the definition, as `testing/unit/upatch_pins.c` does, or in
  `testing/unit/<m>_test.h`, as `curl_test.h` does.

The build needs no rule: `Makefile.shirudo` builds every
`testing/unit/*.c` into `build/unit/<m>` against
`build/unit/libshirudo.a`, the archive of the util objects, and
`testing/Makefile` lists it among the suites. A suite for code outside
`util/` names its object, as `quote_check` and `jar` do:

```make
build/unit/<m>: UNIT_OBJS := tools/<tool>/<file>.o
build/unit/<m>: tools/<tool>/<file>.o
```

## What a case runs in

`testing/unit/unit.c` forks each case from the suite's `main()`, with a
60-second `alarm()`:

- A crash, a sanitizer abort, an `ASSERT_*` or a hang fails that case
  alone (`# timed out`, `# Segmentation fault`).
- Nothing a case changes reaches the next: globals, `setenv()`, the
  working directory, a namespace. Each case starts from the state the
  suite had before the first, so set up inside the case, with a helper
  such as `use_log()` in `testing/unit/eventlog.c`.
- What a failing case wrote to standard error comes back as `#` lines.
  Standard output is the TAP stream itself: write diagnostics to
  `stderr`, never `printf()` in a case.

CI runs the suites as root, in the Build workflow's VM and under `sudo`
in the CI suite; on a workstation they run as you. Write each case to
pass both ways:

- A case that needs root skips without it: `need_root()` in
  `testing/unit/io.c` calls `unit_skip()` when `geteuid()` is not 0.
- A result that differs for root takes both, as `io.c` does with
  `geteuid() ? -EPERM : 0` for a sticky directory.
- A case whose result depends on the host checks the host and skips:
  `testing/unit/upatch_pins.c` skips when the host has shirudo pins.

## Fakes

The tree has no mocking library. These are its ways:

- Files. Make a directory with `mkdtemp()` under `$TMPDIR`, falling
  back to `/tmp`, write fixtures with `open()` and `write_complete()`,
  and remove them at the end of the case (`use_fixtures()` and
  `drop_fixtures()` in `testing/unit/sysinfo.c`). An anonymous file is
  a `memfd_create()`. `testing/unit/archive_test.h` writes a `.bee`
  archive into a descriptor with `archive_write()`.
- A path the code opens itself. Prefer a function that takes the path
  or a directory descriptor and test that. Where the code opens a fixed
  path, or a failure must happen that the kernel does not give on
  demand, wrap the libc call at link time: add
  `build/unit/<m>: LDFLAGS += -Wl,--wrap=<symbol>` to `Makefile.shirudo`,
  define `__wrap_<symbol>()` in the suite and call `__real_<symbol>()`
  from it. `upatch_pins.c` redirects `opendir()` to the case's
  directory and makes `readdir64()` fail with `EIO`; `curl.c` catches
  `curl_slist_free_all()` to read the memory before it is freed. An
  environment variable the code reads is another way in, one the
  target honors and `Documentation/reference/environment.rst` lists:
  use one that exists, as `eventlog.c` sets `SHIRUDO_EVENTLOG_PATH`,
  rather than adding one for a test.
- Mounts. A root case calls `unshare(CLONE_NEWNS)` and makes `/`
  private (`MS_REC | MS_PRIVATE`) before it mounts anything, as
  `open_beneath_same_mount_refuses_a_bind()` in `io.c` does. The
  namespace dies with the case's child.
- Races. Fork a child that does the other side until it is killed, and
  bound the parent's loop (the rename race in `io.c`).
- Time. There is no clock fake: the functions take the time as an
  argument, as `iso8601()` in `util/timefmt.h` does.
- Network. No suite runs a server. HTTP and OTLP parsing is reached by
  the fuzz targets (`oci-http`, `otel`) and by functional tests against
  `testing/helper/test-oci-registry.py` and `otel-mock.py`.

What a unit case cannot show, a C helper in `testing/helper/` and a
shell test can, without a VM: `t4001-tpm-wire.sh` runs
`helper/test-tpm-wire`, and the TPM tests run the libtpms simulator
through `helper/tpmsim-cmd`. The `functional-tests` skill covers those.

## Sanitizers

- ASan and UBSan run without recovery, so a report fails its case.
  CI runs them on every pull request with gcc, with gcc and clang on
  main.
- LeakSanitizer never checks a case: the child ends in `_exit()`, which
  skips the leak check. Free what a case allocates anyway; a leak shows
  only where a fuzz target reaches the code, as libFuzzer checks for
  leaks.
- MemorySanitizer needs instrumented libraries
  (`.github/scripts/msan-deps.sh`) and leaves out `upatch_decode`,
  whose values come from LuaJIT's assembly interpreter.
- ThreadSanitizer (`SANITIZE=thread CC=clang`) runs on main only.
- The build does not track flags: objects of another `CC` or
  `SANITIZE` stay behind. Run a sanitizer build in a `git worktree`
  from `make clean`, as the `pre-submit` skill says.

## Workflow

1. Write or change the cases in `testing/unit/<m>.c`.
2. Build and run that suite alone, after one `make` of the tree:

   ```sh
   make -f Makefile.shirudo build/unit/<m> && build/unit/<m>
   build/unit/<m> <substring>          # only the cases whose name holds it
   ```

3. Run it as the tier runs it, which builds every suite first:

   ```sh
   make -C testing unit/<m>
   ```

4. Build and run it with both compilers:

   ```sh
   make -B -C testing unit/<m> CC=gcc
   make -B -C testing unit/<m> CC=clang-23
   ```

5. In a worktree, from `make clean`, under the sanitizers CI uses:

   ```sh
   make -C testing SANITIZE=address,undefined unit/<m>
   sh .github/scripts/msan-deps.sh && sh .github/scripts/msan-tests.sh 60
   ```

6. Read the TAP: every `not ok`, the `#` lines under it,
   `runtime error:`, `ERROR: AddressSanitizer`, and the reason of each
   `# SKIP`, which can hide a case that never ran. Fix the code or the
   case and go back to step 2.
7. Update `Documentation/contribute/testing/test-coverage.rst`: a
   suite added joins the list under "Unit suites and fuzz targets" and
   its count of modules, and the "Coverage by area" row of its area
   names it. A change to code a CBMC harness reads runs that proof too (the
   `proofs` skill); a parser of input from outside the host also gets a
   fuzz target (the `fuzz-target` skill).
