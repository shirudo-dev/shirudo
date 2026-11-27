---
name: proofs
description: Runs, writes and debugs shirudo proofs: CBMC for bounded C properties, Kani for bounded Rust properties and Lean 4 for algorithm models. Covers choosing the prover, running the proof tiers, and the coverage page; cbmc.md, kani.md and lean4.md explain each kind. Use when changing code a proof covers, adding a parser or algorithm to prove, investigating a failed proof, or when asked to prove code correct.
---

# Proofs

`Documentation/contribute/testing/proofs.rst` explains the commands, and
`Documentation/contribute/testing/proof-coverage.rst` lists each proof,
its bound and the source files without one. When code a proof covers
changes, update the proof in the same commit and run it. A new source
file gets a proof or an entry under "Files without a proof"; the docs
check rejects a file listed in both places or neither.

## Choose the prover

CBMC checks the remaining C within a bound. Kani checks production Rust
within a bound. Lean 4 proves a model of an algorithm for every input,
without reading either implementation. Link a model to Rust with a Kani
comparison proof, or to C with a CBMC comparison proof, where practical.
The coverage page states when correspondence is checked by review alone.

- For a C harness, read [cbmc.md](cbmc.md).
- For a Rust harness, read [kani.md](kani.md).
- For an algorithm model, read [lean4.md](lean4.md).

## Run

```sh
make proofs                                      # CBMC, Kani and Lean 4
make -C testing kani KANI_PROOFS=string_suffix   # one Rust proof
make proofs-cbmc PROOFS=paths-bpffs-name         # one C proof
make proofs-cbmc CHANGED=origin/main..HEAD       # changed C
make proofs-lean4                                # algorithm models
```

The Proofs workflow runs after a push to main. Before sending a change,
run the proofs that cover it. `testing/proofs/kani/proofs.list` selects
Kani harnesses, and `testing/proofs/cbmc/proofs.list` selects the two
remaining C harnesses. Both runners save a failed proof's output under
`build/`. The Kani runner limits a harness to ten minutes and 6 GiB; the CBMC
runner has its own memory and time limits. A proof that exceeds its
limit needs a smaller, behavior-preserving helper or a tighter harness,
with the original input bound retained.

A real bug is fixed in a commit of its own, with the proof that found it
or a unit test, and the proof commit follows.
