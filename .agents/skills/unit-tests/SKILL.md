---
name: unit-tests
description: Writes or changes shirudo unit tests. Rust modules keep cases in a sibling tests.rs and run in one test binary; the remaining C pin-grant suite uses testing/unit/unit.h. Covers case naming, fixtures, shared process state, running one module or case, sanitizer results and coverage documentation. Use when adding a Rust function's unit cases, changing testing/unit/, or debugging a unit failure.
paths:
  - "rust/src/**/tests.rs"
  - "testing/unit/**"
---

# Unit tests

A Rust unit test calls code in its module, in the build host process. It
checks a function, parser or small state machine without a booted target.
A command's output belongs in a functional test; BPF enforcement and
TPM state need a target VM. Read "Choose a tier" in the `testing` skill.

`Documentation/contribute/testing/testing.rst` ("Write a unit test")
is the reference. The `coding` skill applies to Rust tests too.

## A Rust module's cases

Put `tests.rs` beside the module and declare it there:

```rust
// rust/src/util/hex.rs
#[cfg(test)]
mod tests;

// rust/src/util/hex/tests.rs
use super::*;

#[test]
fn decode_refuses_non_hex() {
    assert_eq!(decode(b"zz", &mut [0u8; 1]), Err(-EINVAL));
}
```

Name each case for what must hold. Check accepted input, boundary values,
invalid input and the exact error. Assert the result and any output the
function may have changed. A case that only repeats the function's
implementation gives little evidence; write one that would fail if a
check were removed. Keep fixtures small and show why each byte matters.

The crate's `rust/src/testutil.rs` provides:

- `TempDir::new()` for a private directory, removed on drop; use
  `join()` for a path and `cpath()` where an older C-shaped API still
  needs a C string.
- `testing_path()` for checked-in fixtures under `testing/`.
- `serial()` for a test that changes process-wide state, such as
  standard streams or environment. Every case that can touch that
  state must take the lock.

Rust test cases run on threads in one process. They do not get the
isolation of a child process. Keep files and mutable state private to
the case; use the existing thread-local test hook when a module reads
a fixed path, as eventlog and tree state do. Do not let one case's
setup determine another case's result.

Prefer an interface that takes a path, descriptor, clock value or
other dependency over a global fake. For an error the real system is
hard to produce, use the module's existing test seam or a small
function parameter; keep production behavior identical.

Root-dependent cases still belong here when the behavior can be tested
in one process. Skip a case without root when it needs root, as
`rust/src/util/io/tests.rs` does for a bind mount. Accept both expected
results when root changes an outcome, and unshare a private mount
namespace before a test changes mounts. An LSM decision belongs in a
target functional test, where enforcement is active.

## The remaining C suite

`testing/unit/pin_grant.c` tests the helper used by BPF code. It keeps
the `unit.h` harness: one `static` function per case, `UNIT_CASE()` in
a terminated table, and `UNIT_SUITE()`. `EXPECT_*` records a failure;
`ASSERT_*` ends the case when later checks need the value. The harness
forks each case and prints TAP. Read that file before extending it.
Do not add C suites for Rust modules.

## Run and read

Build and run one module with:

```sh
make -C testing unit/hex
```

`testing/Makefile` discovers a module by its `tests.rs`, builds
`build/unit/shirudo-unit`, and `testing/run-tests.sh` selects its test
names. The same runner builds and runs `unit/pin_grant`. For one Rust
case after a build, run the binary with its full test name:

```sh
build/unit/shirudo-unit 'util::hex::tests::decode_refuses_non_hex' --exact
```

Run `make -C testing unit` for every suite. Read every failed case and
its panic text, and check skipped or filtered cases rather than
counting a successful exit as proof that the intended case ran. CI
also runs sanitizer builds; a memory report fails the suite. `make -C
testing valgrind` and `make -C testing miri` cover the subsets their
runners support. Use the `testing` and `pre-submit` skills for those
runs and for compiler variants.

Update `Documentation/contribute/testing/test-coverage.rst` when a
suite is added or its claim changes. A parser of untrusted bytes also
needs the fuzz target appropriate to its boundary; consult the
`fuzz-target` skill. Run the existing proof if the changed code is
within a proof's scope.
