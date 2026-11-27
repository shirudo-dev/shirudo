# CBMC proofs

- Add a proof
- Write
- Keep it fast
- When it fails

## Add a proof

1. Write `testing/proofs/cbmc/<name>.c` as "Write" below says, named
   for what it proves the way the others are (`string-number`,
   `upatch-header`, `bpm-tar-header`).
2. Add its line to `testing/proofs/cbmc/proofs.list`: the name, tabs,
   then its options, a small `--unwind`, an `--unwindset` for each loop
   the data bounds and the `LEN=` sizes it runs at, as the lines there
   show.
3. Run it, `make proofs-cbmc PROOFS=<name>`, and read the traces with
   `testing/proofs/cbmc/run.sh -v <name>`. It has to fit the 6 GB and
   60 minutes CI gives one proof.
4. Break the code it proves, see the proof fail, and restore the file.
5. Add its row to the "CBMC proofs" table of
   `Documentation/contribute/testing/proof-coverage.rst` (proof, code,
   inputs, properties), and take every file it now reads off "Files
   without a proof" there. `.github/scripts/check-docs.sh` fails on a
   proof without a row and on a file a harness reads that the list
   still names.
6. Commit it with the code it covers, or after the fix for the bug it
   found.

## Write

- `testing/proofs/cbmc/<name>.c` includes `"proof.h"` and the `.c` it
  proves, and defines `harness()`. Inputs come from `any_bytes(n)` and from
  variables left uninitialized; `__CPROVER_assume()` bounds them and
  `__CPROVER_assert(cond, "what holds")` states each property.
- Only a local left uninitialized is any value. A `static` or global
  object of a harness is zeros, as in C: a table meant to be any table
  takes each entry from a local, or the proof runs on the one empty
  table and holds of nothing else.
- State the contract, not the implementation: which inputs are accepted,
  that every offset or pointer returned lies inside the input, that a
  refusal writes nothing, that output reads back. Proving the code equal
  to a reference that computes the same arithmetic is hard for the SAT
  solver and proves little more: an exact value check belongs on short
  inputs only.
- Prefer a harness that holds for inputs of every size: when the code
  reads a fixed-size part, give it exactly that many bytes and leave the
  size it is told symbolic, as `upatch-header.c` does.
- Then run it on broken code: make a loop read one byte too many or drop
  a check, see the proof fail, and restore the file.

## Keep it fast

- A length CBMC keeps symbolic makes every access to the buffer costly.
  Run the proof once per length instead: `LEN=0-6`, `LEN=16,64` or
  `LEN=0-24,28,32` in `proofs.list`, with the harness using `LEN`.
- A global `--unwind` unrolls every loop that far, including those whose
  count comes from the data. Give each loop its bound with
  `--unwindset <function>.<n>:<bound>` (`goto-cc --function harness ... -o
  x.goto; goto-instrument --show-loops x.goto` names them) and keep the
  global one small; the unwinding assertions fail the proof if an input
  needs more, so a tight bound is safe.
- A loop the input cannot reach at the harness's sizes takes bound 0, as
  the policy labels do in data too short to hold one. CBMC still runs
  its body once to the unwinding assertion, so a costly body bounded 0
  is better kept out of reach by the harness, as `upatch-signed-sections`
  does with no maps.
- `too many addressed objects` asks for `--object-bits 12`.
- Division and remainder cost the SAT solver most: `--refine-arithmetic`
  took one proof from 360 s to 21 s, though it slows others. Time both.
- Code that reads a file goes through the `PROOF_FILE` models of
  `proof.h` (`getline()`, `pread()`, and an `errno` that keeps its value:
  CBMC's own changes at every read, so an `EINTR` retry loop never ends).
  `any_input(len, max)` covers inputs of every length for code that reads
  at most `max` bytes. A `pread()` model that may fail made one proof take
  18 GB; let it succeed and prove the failure paths apart.
- A `memchr()` over thousands of bytes unrolls slowly. Where the caller
  only asks whether the byte is there and `n` is a constant, define
  `PROOF_MEMCHR_QUANTIFIED` before including `proof.h` for a quantified
  model; it returns any match, not the first.
- A cast the code means, such as `(__u32)insn.imm`, fails
  `--conversion-check`. Include the file between `#pragma CPROVER check
  push`, `#pragma CPROVER check disable "conversion"` and `#pragma CPROVER
  check pop`, and keep the check on everywhere else.
- An array larger than `--max-field-sensitivity-array-size`, 64 by
  default, is one object to CBMC, so the bytes stored in it stay
  symbolic to every later read and comparison, constant strings
  included. A proof that rests on such an array's contents raises the
  bound to its size, as `bpm-tar-header` takes 512 for the tar header
  and `bpm-tree-sync-model` 257 for the tree's 256-byte strings.
- A write at a symbolic index makes every later read of that array
  symbolic, and a heap object of symbolic size blows up memory: give an
  allocation a fixed size the harness bounds. A write through a pointer
  into a big struct becomes an update of all of it; index the member in
  place, as `sep()` of `util/json.c` does.
- `proof.h` models `vsnprintf()` for `%s` and `%d`, `%u`, `%x`, `%o` with
  a zero flag, a width, written out or `*`, and `ll`, and fails a proof
  on any other conversion; CBMC does not promote variadic arguments, so
  the model reads each by its size. `%o` writes each digit at a place
  known beforehand, as `bpm-tar-writer` needs of the tar header's fields.
- A struct of tens of kilobytes, such as a tree operation, makes even a
  few symbolic copies slow: prove the logic that reads its fields on a
  smaller harness, or leave it to the unit cases. CBMC reads a member
  through a pointer at an index it does not know as bytes at that offset
  of the whole array: give each array a pointer may be into an object of
  its own, as `bpm-tree-sync-model.c` does each publication's
  operations, and let a stub fill what it returns on every path, so
  that the offset into each is known where the code reads it.
- A proof over a few hundred symbolic bytes with long string scans can
  take minutes: split it, proving the parts the caller composes, as the
  `.upatch` header, sections and decoders are proven apart.
- `--write-solver-stats-to <file>` writes the clauses each instruction
  adds; summed by source line, they show what makes a formula big. CBMC
  takes the first of an option given twice, so try another value in
  place of the one `proofs.list` gives, not after it.

## When it fails

- `no body for function <f>`: CBMC lets that call return anything, so
  `run.sh` fails the proof. Add a model of `<f>` to `proof.h` or keep the
  proof away from it.
- A failed `__CPROVER_assert` or bounds check comes with a trace under
  `-v`. Rebuild the input it names as a unit test or a small C program
  before calling it a bug: a harness that assumed too little or stated
  the property wrongly fails too.
- A trace in which a copy yields bytes that are in neither its source
  nor its destination, from a literal chosen by symbolic data, is CBMC
  5.95's `memcpy()` model, not the code: rerun the input as a constant
  to confirm, then define `PROOF_MEMCPY_BYTEWISE` before including
  `proof.h` (as `bpm-upatch-member.c` does). Such a copy is also
  pathologically slow, wrong bytes or not: when a proof stalls in
  `memcpy()`, look for a literal source chosen by symbolic data first.
- CBMC 5.95 also reads wrong bytes at a symbolic offset from a heap
  object of struct type that a `memcpy()` filled, `xreallocarray()`'s
  for one; a wrong value can make a check pass as well as fail. Read
  such an object by its members, never cast to bytes.
- It does so without a `memcpy()` and on the stack too: a read through a
  `char *` at an index that depends on the data, as
  `release[strlen(prefix)]` is, from an object whose type starts with an
  array of `char`, as `struct tree_selector` and `struct utsname` do, is
  taken from that first member. Hold such an object inside one that
  starts with another type, as `bpm-tree-overlap-model` holds a selector
  in a `struct tree_operation`, and keep a harness's own reads at
  indices its loops give.
- `run.sh` passes `--unsigned-char`, as the build passes
  `-funsigned-char`; a conversion failure on `char` elsewhere means the
  proof is not built as the code is.
