---
name: fuzz-target
description: Adds or extends a libFuzzer target for a shirudo parser of input from outside the host. Covers the harness and the properties it should hold the parser to, the Makefile rule, seed inputs, the coverage table, and running a target and reproducing what it finds. Use when adding or changing a parser of registry, package, upatch, config, evidence or collector input, or when a fuzz run fails.
---

# Fuzz targets

Every parser of input from outside the host gets a target in
`testing/fuzz/`, built with clang under ASan and UBSan and run by
`make -C testing fuzz`, as CI does.

## The harness

`testing/fuzz/fuzz-<name>.c` defines `LLVMFuzzerTestOneInput()`. System
headers come first, then `"fuzz.h"`, then shirudo's headers, which
poison the libc names they replace. A target that reaches a static
function includes its `.c` file, a builtin's too, with a stub that
`abort()`s for each function the builtin calls only on paths the target
does not take, as `fuzz-bpm-info.c` does. A parser that reads a file by
name gets one from `fuzz_file()`, or `fuzz_gzip_file()`, both in
`fuzz.h`. A target whose code prints sends stdout to `/dev/null` in
`LLVMFuzzerInitialize()`, as `fuzz-rodata.c` does, and one that needs a
directory makes it under `TMPDIR` and removes it `atexit()`, as
`fuzz-config-update.c` does.

A target of what a command prints from a file it has not verified calls
`fuzz_output_capture()` in `LLVMFuzzerInitialize()` and runs the command
as the CLI does with `fuzz_run()` of `testing/fuzz/output.c`, as
`fuzz-upatch-info.c` does. That holds what the command printed to the
promise of `text_sanitize()` for a terminal, or to one JSON document
after `--json`, and `fuzz_output()` returns it for a target's own checks.
The command must not reach the network, the kernel or the TPM: give it a
local file and options that keep it off those paths.

Not crashing is the least a target checks. Make it `abort()` when a
property of the parser breaks:

- what it accepts and emits again reads back the same, as `fuzz-tree.c`
  holds a tree publication and its operation digests;
- what it writes reads back as its format, as `fuzz-quote-check.c`
  holds the line of a verdict to JSON;
- offsets and sizes it returns lie within the input, as `fuzz-rodata.c`
  holds the `.rodata` range;
- two ways to the same value agree, as `fuzz-attest-report.c` holds the
  text and the JSON report of `attest verify` to the same checks and
  verdict.

A property holds for every input. Where a valid input may legitimately
exceed a bound, such as output nested deeper than the reader goes,
state that exception exactly, or the target reports its own error.

## Wire it up

- `Makefile.shirudo` picks up every `testing/fuzz/fuzz-*.c` as a
  target. Add a rule naming its sources, `$(FUZZ_BASE)` and the `util/`
  files it needs. A target that includes a `.c` file names it in
  `FUZZ_INCLUDED`, so that it is not linked twice.
- Seed inputs go in `testing/fuzz/corpus/<name>/`: small valid inputs
  that reach each branch of the properties, named after what they show.
- Add the target to the fuzz table of
  `Documentation/contribute/testing/test-coverage.rst`.

## Run it and reproduce a finding

```sh
make -C testing fuzz FUZZ_SECONDS=60           # every target, as CI
sh testing/fuzz/run.sh 300 <name>              # one target for longer
testing/fuzz/fuzz-<name> testing/fuzz/crash-<name>-<hash>
PATH=$PWD/build/afl/bin:$PATH make -C testing afl FUZZERS=<name>  # AFL++
```

A new target needs nothing more for AFL++: `make -C testing afl` builds
every `fuzz-*.c` with `afl-clang-fast` as it is. A failure leaves its
input in `testing/fuzz/crash-<name>-*`, or `crash-afl-<name>-<n>` from
AFL++, which git ignores. Fix the parser, or the harness when the property was wrong,
add the input to the corpus when it shows a case the seeds do not, and
delete the crash file. libFuzzer's own `-jobs` writes `fuzz-<n>.log`
into the current directory: run that from a scratch directory, not the
checkout. Use clang 23, `FUZZ_CC=clang-23` where the host's `clang` is
older.
