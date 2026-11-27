# Lean 4 proofs

## Add a model

1. Write `testing/proofs/lean4/Shirudo/<Name>.lean`, with the SPDX and
   copyright lines of `testing/proofs/lean4/Shirudo.lean`, following
   the C as "Rules" below says.
2. Import it from `testing/proofs/lean4/Shirudo.lean`.
3. Run `make proofs-lean4`: it builds every module with warnings as
   errors, then checks each proof again with `leanchecker` and nanoda.
4. Link the model to the C with a CBMC proof where one is cheap, as
   `string-number-model` does; otherwise the coverage page says it
   follows the C by review.
5. Add its row to the "Lean 4 proofs" table of
   `Documentation/contribute/testing/proof-coverage.rst`: the module
   and the C it models, the theorems, the assumptions each rests on,
   and how it follows the C.

## Rules

- A model goes in `testing/proofs/lean4/Shirudo/<Name>.lean`, imported
  from `Shirudo.lean`, and follows the C step by step, with the values the
  C can hold (2^64 for a `__u64`).
- What the C cannot show, such as a hash being collision resistant, is
  an explicit hypothesis of the theorem, never an axiom.
- Core Lean only, no Mathlib: `omega`, `simp`, `decide` and induction
  carry these proofs. A lemma Mathlib has, such as
  `List.map_injective_iff`, is proved in the file.
- The lakefile builds every module under `Shirudo/`, imported or not,
  and makes every warning an error, so a `sorry`, a deprecated name or
  an unused `simp` argument fails the build.
- `run.sh` then checks every proof again, with Lean's kernel
  (`leanchecker`) and with nanoda, a kernel written apart from Lean,
  which admits only the axioms `nanoda.json` permits: `propext`,
  `Classical.choice` and `Quot.sound`. A `native_decide`, which rests
  on the compiler, or an `axiom` of our own stops nanoda with
  `declaration not found` and the name. Prove with `decide`, `omega`
  or `simp` instead, and keep `nanoda.json`'s list as it is.
- A model proves the algorithm, not the C. Link the two with a CBMC
  proof where one is cheap, as `string-number-model.c` checks
  `parse_u64()` against `Number.lean` up to 4 bytes and
  `bpm-tree-sync-model.c` runs the tree sync against `TreeSync.lean`'s
  steps; the coverage page says which models follow the C by review.
- The toolchain is the one `lean-toolchain` names; elan installs it.
