---
name: fuzz-target
description: Adds or extends a libFuzzer target for a shirudo parser of input from outside the host. Covers a Rust module's fuzz.rs, its properties, the Makefile target, seed inputs, the coverage table, and reproducing a finding. Use when adding or changing a parser of registry, package, upatch, config, evidence or collector input, or when a fuzz run fails.
---

# Fuzz targets

A parser of input from outside the host gets a target under the Rust
module it tests. `make -C testing fuzz` builds and runs the targets with
clang, ASan and UBSan. The TPM command parser is the remaining C target,
`testing/fuzz/fuzz-tpm-command.c`.

## Write the target

Put `fuzz.rs` beside the module's `tests.rs`, as
`rust/src/util/upatch/fuzz.rs` does. Register the module under
`#[cfg(shirudo_fuzz)]` and use `fuzz_target!()` from
`rust/src/fuzzing.rs` to export a run function and an initialization
function. `testing/fuzz/target.rs.in` gives each target the libFuzzer
entry points; it calls those Rust functions. For a parser that takes a
file path, `fuzzing::input_file()` holds the bytes in a memfd and gives
the parser a path. `input_gzip_file()` gives it gzip input.

A target of a command that prints unverified input runs both its text
and JSON forms, and checks the output with `StdoutCapture`, as
`rust/src/builtin/upatch/info/fuzz.rs` does. Keep the target off network,
kernel and TPM paths by giving it local input and the options that
avoid those operations.

A target checks a property as well as whether the parser crashes:

- What it emits must parse back to the same publication, as
  `rust/src/util/bpm_tree/fuzz.rs` checks.
- Offsets and sizes returned for an input must lie inside that input.
- Two forms of a report must agree on the same checks and verdict.
- A refusal must not leave a partial output a caller could accept.

Abort when a property breaks. State an exception explicitly when a
valid input can exceed a bound, or the target will report its own error.

## Wire it up

- Add the target name to `FUZZ_NAMES` in `Makefile.shirudo`. Its rules
  compile `target.rs.in` for that name and link it with the
  instrumented Rust library. Keep the two exported symbol names in
  `fuzz.rs` consistent with that name.
- Put small valid seeds in `testing/fuzz/corpus/<name>/`, named for the
  branches and properties they reach.
- Add the target to the fuzz table in
  `Documentation/contribute/testing/test-coverage.rst`.

## Run and reproduce a finding

```sh
make -C testing fuzz FUZZ_SECONDS=60
sh testing/fuzz/run.sh 300 <name>
testing/fuzz/fuzz-<name> testing/fuzz/crash-<name>-<hash>
PATH=$PWD/build/afl/bin:$PATH make -C testing afl FUZZERS=<name>
```

`run.sh` leaves a failing input under `testing/fuzz/crash-<name>-*`.
Reproduce it with the target binary, then fix the parser or the
property, add the input to the corpus when it covers a case the seeds
miss, and remove the crash file. Run libFuzzer's own `-jobs` from a
scratch directory so its logs stay out of the checkout. Use clang 23,
`FUZZ_CC=clang-23` when the host's clang is older.
