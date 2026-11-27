# Claims against the code

The threat model and the proofs are claims about the tree. Check both
at the commit the audit reads.

- Threat model against the code
- Proofs against the code

## Threat model against the code

The threat model is a list of claims about the tree, and the tree moves
under it. `.github/scripts/check-docs.sh` checks that the hooks,
counters, tests and proofs a fact box names exist, not that a claim
holds. Check the claims in both directions.

From the page to the code, take one claim at a time: a sentence of a T
entry, a field of its fact box, the "Checked by shirudo" column of an
assumption, an R or U entry. Find where it would be enforced, read that
code and its callers, and give the claim one of these:

- it holds, on every path, with file and line;
- it holds in part: on the paths a test takes and not on another. This
  is the answer that matters most, and a finding when the path left
  out is an adversary's;
- the code contradicts it, or nothing enforces it. For an absence, say
  where you looked: a search that stopped early reads like one;
- the code does more: a check no claim names, which the next change
  can drop unnoticed;
- it cannot be checked: too vague to hold code to, a bug of the page.

In a fact box, each hook refuses what the prose says, to every caller
the prose names, with the error it names; each counter moves on that
refusal; each bound the prose gives, such as 1024 mounts or 8 MiB, is
the constant in the code; and each test fails when the refusal is taken
out, which for the hooks behind G1 and G2 is worth doing in a scratch
worktree. An R or U entry is still true and no wider than stated, and a
U entry whose status is a code-path reading is one to reproduce or
refute.

From the code to the page: every LSM program of `bpf/`, every tamper
counter, every `bpf()` command the gates admit, every command, option,
environment variable, file, unit and linked library stands behind some
T, A, R or U entry, or is named as support for one. `git log
<the page's last commit>.. -- bpf util 'builtin-*.c' systemd` lists
what moved since the page did.

A disagreement is the page's bug when the code does what the design
means, and a finding when a goal rests on the claim. Decide which
before rating it; the page changes with the fix either way.

## Proofs against the code

The proofs of `testing/proofs/` are evidence only while they hold for
the code as it is, and CI runs them only after a push to main, without
the CBMC proofs `testing/proofs/cbmc/ci-skip.list` names. An audit runs
all of them at the commit it audits, `make proofs`, those on that list
for hours each, so start it first as the `proofs` skill says, and
reports the commit and the result. A failure is sorted like any
candidate: a bug in the code, a harness that assumed too little, or a
proof the code left behind.

A proof that passes can still prove less than its row in
`Documentation/contribute/testing/proof-coverage.rst` says. For each
CBMC proof a fact box names, and each one the audit leans on:

- it includes the `.c` it proves, not a copy, and no model of `proof.h`
  stands in for the function under proof or decides its property;
- every `__CPROVER_assume()` is something each caller makes true: find
  the caller. An assumption no caller guarantees hides the inputs it
  excludes;
- its bounds reach the code's: `LEN`, the unwind bounds and the buffer
  sizes of the harness against the constants of the code, which may
  have grown since;
- it reaches the code: with `--cover location` CBMC marks every block
  no input of the harness gets to as `FAILED`, among them whatever an
  assumption cut off;
- its assertions state what the row and the callers need, for every
  field, branch and return code the function has now (`git log -p
  <the harness's last commit>.. -- <file>`);
- it fails on broken code: drop a check or read one byte further, see
  it fail, restore the file.

```sh
cd testing/proofs/cbmc    # options: the proof's line in proofs.list
cbmc --function harness -I ../../.. -I ../../../include -I ../../../util \
     -I ../../../vendor/libbpf -I ../../../vendor/libbpf/include/uapi \
     -D_GNU_SOURCE --unsigned-char <options> [-DLEN=<n>] \
     --cover location <proof>.c | grep 'util/.*FAILED'
```

For each Lean 4 model: `Shirudo.lean` imports it, no `axiom`, `sorry`,
`native_decide` or `unsafe` stands in it (`#print axioms` on a theorem
a row names shows what it rests on; `run.sh` fails on any axiom
`testing/proofs/lean4/nanoda.json` does not permit, so check that its
list still holds only `propext`, `Classical.choice` and `Quot.sound`),
and each hypothesis of a theorem is something the C or the deployment
makes true. Where the coverage
page links the model to the C by a CBMC harness, that harness and its
bound are the link. Where it says review, review again: read the C
beside the model step for step, with every constant, the order, each
branch and each error path, and every commit to the C since the model
last changed.

Then the gaps. The coverage page lists the files no harness reads
under "Files without a proof", each with the reason, which
`check-docs.sh` keeps complete, and under "Not covered yet" what the
proofs of the other files leave out. Every parser of outside input,
every emitter whose output is hashed, signed or measured, and every
protocol with crash states has a proof or stands in one of the two.
Read each reason against the file: "calls the kernel" stops being one
for logic that can move out from between the calls. A function of a
proven file that no harness reaches and the page does not name is a
gap too, and so is the code that joins proven parts. Where neither a
proof nor a fuzz target reaches, hunt first.

A proof out of sync with the code is a security bug, whichever of the
two is right: a fact box or a coverage row then claims an assurance the
tree does not have. Report each as a finding: a proof that fails, an
assumption no caller makes true, a bound the code has outgrown, a model
the C has left, code a row calls proven that no harness reaches. It is
the one kind of finding that names no adversary, since what it breaks
is the evidence the others are judged by. Rate it low while the code
turns out sound, and by what it breaks where the gap hid a defect. The
fix brings the harness or the model, its line in `proofs.list` and its
row on the coverage page back in step in one commit, or fixes the code.
