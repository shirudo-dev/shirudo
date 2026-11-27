# Kani proofs

Kani checks production Rust for every input within a harness's stated
bound. A harness belongs beside the code it checks in a module gated by
`#[cfg(kani)]`; normal builds do not include it.

## Add a harness

1. State the behavior independently of the implementation. Read the
   corresponding C proof when porting one and keep its input bound or
   increase it. A comparison with a Lean model derives its reference
   from the Lean definition, cited in a comment.
2. Mark the harness `#[kani::proof]`, use `kani::any()` for symbolic
   input and `kani::assume()` only for real preconditions. Assertions
   state the contract. Do not duplicate production logic as the oracle.
3. Add its name to `testing/proofs/kani/proofs.list` and its property,
   bound and source file to `proof-coverage.rst`.
4. Run `make -C testing kani KANI_PROOFS=<name>`. Read
   `build/kani/<name>.log` after a failure. Deliberately break the
   property and confirm the harness detects it before restoring code.
5. Run all Kani harnesses and the normal build and lint gates before
   handing back a batch.

`testing/proofs/kani/version` pins the toolchain for the local runner
and CI. The runner caps each proof at ten minutes and 6 GiB. Large symbolic
allocations or variable length loops can make a solver run out of time:
use fixed lengths that together cover the same bound, or extract a
small production helper in a separate behavior-preserving commit.
A harness that models an OS, TPM, cryptographic or network operation
proves only the modeled state change. Integration and VM tests cover
that boundary.
