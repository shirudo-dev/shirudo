---
name: security-audit
description: Audits shirudo for vulnerabilities against its threat model, and checks the threat model and the CBMC and Lean 4 proofs against the code. Covers what makes a finding, where untrusted bytes and root's actions enter, the bug classes of shirudo's C and BPF, refuting, reproducing and rating a finding, and hunting its variants. Use when asked to audit or security-review shirudo or a change, to hunt one class of bug, to check whether a reported issue is real, or to check the threat model or proofs against the tree. Runs only on the strongest model at xhigh effort, as its first section says.
effort: xhigh
---

# Security audit

## Model and effort

A weaker model returns the same confident list with less behind it, and
nothing in its report shows the difference. Run an audit in Claude Code
on Claude Mythos 5.2 or newer at `xhigh` effort, and in Codex on the
GPT-6 cyber model or a better one, at the effort that matches; in
another agent, on that vendor's equal of the two. The frontmatter sets
the effort in Claude Code, for the turn that loads this skill, and
other agents ignore it. It names no model: it could name only one, and
would hold a newer one back.

Before the first step, say which model and effort the run has. On less
than that, or when you cannot tell, stop and ask for the switch: do not
audit, and do not carry an audit on at less in a later turn. Work
handed to another agent runs on the same model and effort; a smaller
model may find code, never judge it. The report names both.

## Findings

`Documentation/security/threat-model.rst` decides what a vulnerability
is: its goals (G1 to G8), assumptions (A), trust boundaries, adversaries
(ADV-A to ADV-G), threats (T), residual risks (R) and threats to resolve
(U). Read it, and `Documentation/internals/architecture.rst`, before
hunting. A finding names five things; one that cannot is not a finding:

- the adversary, and what it controls: bytes it serves, a file it
  writes, a syscall it makes, a mount it sets up, an interrupted command;
- the control that should stop it: a signature check, a hook, a gate,
  a bound, the register lock, a measurement;
- the boundary it crosses (the trust boundaries section);
- the goal it breaks, or the asset it reaches;
- the result observed, no stronger than what was seen.

Root on the target (ADV-B, and ADV-C with mount namespaces and devices)
is the main adversary: root is not trusted because it is root, so
"needs root" never dismisses a finding. A path that starts from a
changed TCB (the kernel, the runtime image, the TPM, the initrd, a task
with runtime authority) breaks an assumption instead, while one that
gets there is a finding; a path that needs the signing key is one only
when it reaches beyond ADV-F's blast radius. What AGENTS.md and the
threat model's own section put out of scope stays out of it, local
denial of service and the correctness of a signed upatch included. An R
or U entry is known: report only a path, a consequence or a
reproduction it does not describe.

## Scope and order

Say at the start what the pass covers: the whole tree, some rows of
the table below, one class, a change, or one reported issue. Take
first what an adversary reaches first and gains most from: bytes from
the network before their signature is checked, then root against G1
and G2, then the rest, and code that changed since the last pass
before code that did not.

For a change, the diff names the rows it touches. A check it removes
or moves is read first: `git log -S'<the check>'` finds the commit
that added it and why. Then the threats whose fact boxes name the
hooks and functions touched, the tests and proofs behind them (`make
proofs-cbmc CHANGED=<range>` runs the proofs that read a changed
file), and every caller of a changed `util/` function, since each
relied on what it did before.

For a reported issue, restate it as the five things before reading
code, then take it through "Refute it".

## Where untrusted input enters

| Entry | Adversary | Code | What must hold |
|---|---|---|---|
| Registry responses, TLS | ADV-D | `util/bpm_oci.c`, `util/tls_openssl.c` | size bounded before buffering; digest checked before use |
| Packages, indexes, tar | ADV-D, ADV-F | `util/bpm_package.c`, `util/bpm_state.c`, `builtin-bpm.c` | signature before trust; no member leaves its directory |
| Tree publications | ADV-D | `util/bpm_tree.c`, `util/bpm_tree_state.c` | only signed operations, generations only forward (R8 is what remains) |
| `.upatch` files | ADV-B, ADV-D | `util/upatch*.c`, `builtin-upatch.c` | every offset bounded before the kernel sees the loader |
| Decoders, map records | ADV-F; ADV-A and ADV-B through what is recorded | `util/upatch_decode.c`, `util/serializer.c` | no `io`, `os`, `ffi` or loaders; instruction and memory budgets; every slot read bounded |
| Config images, settings | ADV-B | `util/config*.c`, `util/image_*.c`, `util/dm_verity.c` | exact UKI root; mapping read fully before parse |
| Evidence | the target | `util/attest.c`, `util/eventlog.c`, `builtin-attest.c` | only the quote and NV certify are authenticated |
| TPM replies | ADV-C (T14) | `util/tpm*.c`, `util/chain.c` | every size field bounded; no success reply taken unauthenticated |
| Files, pins, xattrs, mounts, `/proc`, environment | ADV-B, ADV-C | `util/seal.c`, `util/paths.c`, `util/io.c`, `builtin-init.c` | act on the object checked; lock spans |
| `bpf()`, LSM hooks | ADV-A, ADV-B | `bpf/bpf2.c`, `bpf/seal.c` | every syscall path to the same effect |
| Collector replies | ADV-E | `util/upatch_maps_otel.c` | changes no state; text sanitized |
| Operator inputs, key | ADV-D | `tools/shirudo-build/`, `util/sign.c` | key stays on the operator; stateless; what a registry serves is pinned |

The fuzz targets in `testing/fuzz/` list the parsers of outside input,
and `Documentation/contribute/testing/proof-coverage.rst` says which
parts CBMC proves: start where neither reaches.

AGENTS.md lists the invariants that are easy to break. Each still
builds and passes its tests when broken, so walk them. Some have a
check to run: `.github/scripts/check-operator-linkage.sh` and
`check-static-target.sh` for what the binaries link, the `no_exec`
rule of `testing/coccinelle` for a target subprocess, and for each map
of `bpf/` the list of who writes and reads it, set against its flags.

## Bug classes that matter here

Read [bug-classes.md](bug-classes.md) before hunting: the kernel source
to keep open, the Coccinelle rules that find the mechanical shapes, and
each class that matters in shirudo's C and BPF, with where it hides
here.

## Claims against the code

Read [claims.md](claims.md) when the pass checks the threat model or the
proofs against the tree, which every whole-tree pass does: how to check
each claim in both directions, and how to run, read and judge the CBMC
and Lean 4 proofs at the audited commit.

## Refute it

A model that hunts favors what it found and rates it too high. Before
a candidate is shown or reported, try to break it:

- restate it as the five things in one sentence: many fall here;
- read back from the flaw to the entry for a check upstream, and on to
  the effect for one downstream. Cite each guard by file and line, read
  in this pass: a page, a test's name, a commit subject or the memory
  of an earlier pass is not evidence that a check exists or that a bug
  is fixed;
- ask whether the adversary reaches the first step without holding
  what the last one gives;
- for a bound, do the arithmetic with the limits the code enforces;
  for a race, say what changes the value between check and use, and
  who;
- hand it to a reader that did not find it, with the code and the
  claim and without the argument, to refute. Where no second reader
  ran, the report says so.

Keep what fell in the report, with the reason: the next pass does not
repeat it, and two that fell alone may hold together.

## Show it

Use the smallest local proof that shows the result. The `testing`,
`fuzz-target` and `proofs` skills say how to run each one.

- a unit case in `testing/unit/`, or a harness linked against
  `build/unit/libshirudo.a`, for a parser or a helper;
- a crafted input run by the fuzz target, under ASan and UBSan;
- a CBMC harness for a bound that must hold for every input;
- a functional test in the test VM (`make -C testing functional/<family>`)
  for anything that needs the LSM, the keyrings or the TPM: the host is
  never a target.

Use the test keys and fixtures, and only the local registry and
collector containers of the end-to-end tier, never a real registry,
collector or key. Stop at the minimum effect: a check that passes when
it must refuse, an unmeasured change, a sanitizer report, a hang past a
bound. When a kernel, deployment or hardware fact outside the tree
decides it, report it as needing validation and name that fact and the
check that settles it.

Say how far each finding was taken, in the words of the threat model's
U entries: reproduced, confirmed in code, or a code-path reading that
is not reproduced. Only the first two are rated.

## Look for its variants

A bug that is found is seldom alone: the mistake behind it was made
with the same helper, on the same assumption, by the same hand. When a
bug holds, a security finding or not, look for its variants through the
whole code base before reporting it: the userspace C, the BPF programs,
`tools/`, the test helpers and the scripts.

- Name the root cause, why the code is wrong and not where: a result
  read by the wrong convention, a length trusted before its check, a
  hook that takes a failed read for no label.
- Write the match for the one instance, with `git grep` or a Coccinelle
  rule, and see that it hits. A match that misses the known bug has the
  bug wrong.
- Loosen it one element at a time, the function, then the callee, then
  the shape of the check, and read every match after each step. Stop
  when most of what comes back is noise.
- Then look where no pattern reaches: the sibling paths to the same
  effect, the other callers of the helper, the other users of the same
  kernel or library interface, the other parsers of the same format,
  and the same assumption made in BPF where it was found in userspace,
  or the other way.

Each variant goes through "Refute it" and "Show it" on its own: the
same shape elsewhere can sit behind a check the first one lacked.
Report the variants of one root cause together, each with its own path
and result, and fix them together. A shape that can be matched
mechanically becomes a rule of `testing/coccinelle` (the
`bpf-coccinelle` skill for BPF code), a property of a fuzz target or a
proof, so that the class stays closed. The report says where the
search went and what it used, so that the next pass does not take a
narrow search for a clean tree.

## Rate and report

Rate only what was shown, by the goal it breaks:

- **critical**: without a key, unsigned BPF loads (G1), enforcement is
  detached (G2), or a verifier accepts a tampered target (G5);
- **high**: root changes shirudo's state or a sealed file unseen (G3,
  G4), a target accepts content its keys did not sign (G7), a process
  without authority reads shirudo's maps (G8), or a registry runs code
  on the operator;
- **medium**: the same with uncommon preconditions (a mount trick, a
  revoked key, a narrow race), a refused attempt leaving no trace (G6),
  or updates stopped on every run;
- **low**: what weakens a control without defeating it, or discloses
  internals that are no secret.

For each finding give the five things above, the threat-model IDs, the
reproduction, and the smallest fix at the last trusted decision point,
in `util/` when other callers need it too, with a regression test that
fails without it. An audit reports: it changes nothing in the tree
unless asked to, and a fix is a change of its own, made as the
`coding`, `testing`, `docs`, `proofs` and `pre-submit` skills say. A
fix updates the threat model: a closed R or U entry leaves it, and a
new gap that stays open gets an entry. What is worth doing but breaks
no goal goes in a separate list of hardening notes, unrated. Report to
whoever asked. A real vulnerability is disclosed only as
`Documentation/security/reporting.rst` says, never in a public issue,
pull request or commit message before it is fixed.

End with what was covered and what was not, by row of the table, class,
T entry and proof: read with nothing found, not read, and out of scope
are three different answers. Give the commit audited, the model and
effort, the result of the proof run, and which findings a second reader
tried to refute. One pass never covers the tree.

## Not findings

- A best practice missed, with no path to a goal.
- An effect claimed stronger than the one observed.
- An R or U entry reported again without anything new.
- A result that needs the TCB changed or an assumption broken.
- A path whose first step needs what its last step gives.
- A same-principal effect: the operator's own input harming the
  operator's host.
