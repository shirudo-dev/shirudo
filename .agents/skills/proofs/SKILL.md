---
name: proofs
description: Runs, writes and debugs shirudo's proofs, CBMC under testing/proofs/cbmc, which checks parsers and emitters for every input within a bound, and Lean 4 under testing/proofs/lean4, which proves models of algorithms for every input. Covers which prover a property needs, make proofs and its CI shards and caps, the coverage page, and in cbmc.md and lean4.md how to add a harness or a model, choose properties and bounds, keep a proof fast and within memory, and tell a real bug from a harness error. Use when changing code a proof covers, when adding a parser, an emitter or an algorithm to prove, when a proof fails, or when asked to prove code correct.
---

# Proofs

`Documentation/contribute/testing/proofs.rst` is the how-to, and
`Documentation/contribute/testing/proof-coverage.rst` lists every proof
and what no proof covers yet. A change to code a proof covers adapts the
harness or the Lean 4 model in the same commit, where the change moved
what it states, and runs that proof (`git grep -n '<file>.c\|<function>'
testing/proofs/cbmc` finds the harnesses that reach the code); a change to
a proof or to what it covers updates the coverage page too. A source
file that is new gets a harness or a line under "Files without a proof"
there, and one a harness starts to read leaves that list:
`check-docs.sh` fails on a file that is neither or both.

## Choose the prover

CBMC proves the C within a bound; Lean proves a model for every input.
Use Lean where a bounded proof is not enough: an algorithm whose
correctness needs every length, such as `Number.lean`'s exact value of a
digit string, or a protocol property, such as `Chain.lean`'s register
determining its events.

Everything else, a parser or an emitter of bytes from outside above all,
gets a CBMC harness.

- Writing or changing a CBMC harness, or a CBMC proof that fails or
  runs too long: read [cbmc.md](cbmc.md).
- Writing or changing a Lean 4 model, or linking one to the C: read
  [lean4.md](lean4.md).

## Run

```sh
make proofs                                  # CBMC and Lean 4
make proofs-cbmc PROOFS="string-number hex"  # some CBMC proofs
make proofs-cbmc CHANGED=origin/main..HEAD   # those reading a changed file
testing/proofs/cbmc/run.sh -v <proof>        # whole output and traces
make proofs-lean4                            # the Lean 4 proofs
.github/scripts/proofs.sh run 3 8            # CI's shard 3 of 8
```

The `Proofs` workflow runs them after a push to main, never on a pull
request, as they take hours of CPU: before a change is sent, run the
ones covering the code you changed, which `CHANGED` picks from what
each harness includes, and all of them after a change to `proof.h`, `run.sh` or `proofs.list`, which `CHANGED` does too. Cap the memory of a long run, `ulimit
-v 24000000` in the shell that starts it: a proof that grows past a few
gigabytes is one to reshape, not to wait for.

CI splits `proofs.list` into eight shards and runs each proof alone
under the 6 GB and 60 minutes `.github/scripts/proofs.sh` caps it at;
a proof added there has to fit both. It leaves out the proofs
`testing/proofs/cbmc/ci-skip.list` names, each with why, which no run
checks unless a developer starts it: run one by hand after a change to
what it reads, and take it off the list once it fits. A proof that
fails in CI prints its whole output, trace included, in its shard's
job log and leaves it in the `cbmc-logs-<k>` artifact. `proofs.sh`
pins CBMC 5.95.1 and elan, and Lean is the release `lean-toolchain`
names; `proofs.sh install-cbmc` unpacks the same CBMC into `build/cbmc`
without root, and `proofs.sh install-headers` installs with `sudo` on
Ubuntu the headers of libcurl, OpenSSL and zlib the harnesses include.

A real bug is fixed in a commit of its own, with the proof that found it
or a unit test, and the proof commit follows.
