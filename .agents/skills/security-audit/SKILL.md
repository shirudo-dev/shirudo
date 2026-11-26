---
name: security-audit
description: Audit shirudo for vulnerabilities against its threat model, and its threat model and proofs against the code. Covers what makes a defect a finding here (the adversary, the control it defeats and the goal it breaks), the surfaces where registry, package, upatch, config, evidence and TPM bytes or root's actions enter, the bug classes that matter in shirudo's C and BPF, checking each claim of the threat model and each CBMC and Lean 4 proof against the tree, refuting a finding before it is reported, showing it with the unit, fuzz, CBMC and VM tiers, looking for the variants of a bug through the whole code base once one is found, and rating and reporting it. Use when asked to audit or security-review shirudo or a change to it, to hunt one class of bug, to check whether a reported issue is real, or to check that the threat model or the proofs still match the code. Needs Claude Mythos 5.2 or newer at xhigh effort in Claude Code, and the GPT-6 cyber model or better in Codex.
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

Hunt each class in both halves, the BPF programs and the userspace C,
and with the kernel source open: a checkout of the kernel the test VM
boots, which `testing/kernel/build-kernel.sh` builds with the carried
patch set. Neither half can be judged without it. For a hook,
read the callers of `security_<hook>()`, what each does with the return
value and what it holds while it calls; for a helper or kfunc, what it
returns, when it fails and whether it sleeps; for a system call, a
`bpf()` command or an ioctl shirudo makes, what its flags mean and which
errors come back; for the verifier, what it has proved and what it
leaves to the program. A statement about the kernel cites file and line
of that tree, as one about a guard does.

`testing/coccinelle` has rules for the mechanical shapes of several
classes below (`openssl_ret`, `errno_clobber`, `alloc_unchecked`,
`fd_leak`, `double_close`, `use_after_free`, `read_unterminated`,
`file_as_string`, `name_after_fd`, the `bpf_` rules): a clean
`check-coccinelle.sh` says those shapes are absent, not the class.

- **Parse before verify.** Anything read before its signature or digest
  is checked (`upatch info`, `bpm info`, manifests, indexes, the
  evidence on the verifier) gets the worst input: offsets, counts,
  integer overflow (`<shirudo/overflow.h>`), recursion, loops and output
  that grow with input.
- **Checked is not used.** The bytes verified differ from the bytes
  loaded or applied: reopened by path, read twice, a file root can
  rewrite after the check, a name resolved through a mount root built,
  a symbolic link in a directory of the path, which `O_NOFOLLOW` does
  not refuse. A check on a descriptor followed by a lookup of the same
  path by name (`realpath()`, `stat()`, `access()`) checks what the
  name leads to then, not what the descriptor was reached through: the
  walk goes one name at a time through descriptors, as
  `check_trusted()` and `seal_open_dir()` do. `open_trusted()` opens a
  name renamed over before its check again and checks each descriptor
  in full; a retry that kept anything from an earlier attempt would be
  this class.
- **Signed, not bound.** A signature covers bytes, not where they are
  used: content signed for another name, version, architecture,
  repository or generation, an index and a package from two
  publications, state brought back from an older copy, a decision that
  rests on the target's clock, which root sets. R1, R8, R14 and R16
  concede the replay of whole signed artifacts: look for the mix a
  check should have refused.
- **Fail open.** An error path that skips a check, a measurement or a
  refusal: label read errors beyond ENODATA and EOPNOTSUPP, a partial
  load, a retry where the design refuses (`tampered`), a default when a
  setting is missing, a short read taken for the whole.
- **Library misuse.** A call that breaks the contract of what it calls,
  in OpenSSL, libcurl, tpm2-tss, libelf, libbpf, zlib, LuaJIT or libc,
  or of a BPF helper or kfunc: a result not checked, or read by another
  library's convention (OpenSSL's 1, 0 and negative, a `TSS2_RC`, a
  `CURLcode`, libbpf's negative errno or NULL, zlib's `Z_STREAM_END`, a
  helper's NULL or negative), an object freed by the wrong owner or the
  wrong function, a buffer or length the callee reads differently, an
  option left at a default the design rules out, an error queue or
  `errno` read after another call overwrote it.
- **Error paths.** The paths tests take least. On every return after
  the first resource is taken, check that what was taken is released,
  what was changed is undone in reverse order, the lock is dropped, and
  the error reaches the caller without a later cleanup overwriting it.
  A partial write, a half-made pin directory or a temporary file left
  behind is state root can use, and a `ret` set and then lost is an
  operation reported as done.
- **Leaks.** Memory, and above all descriptors. A link, program or map
  descriptor that outlives its use keeps the object attached after its
  pin is gone (U17), a leaked secret is never cleared, and a leak per
  item of outside input ends in `EMFILE` or `ENOMEM` at a point the
  input chose. In BPF, what the verifier does not track: a map entry
  never deleted, arena memory never freed, storage that outlives its
  owner.
- **Use after free.** A pointer into a buffer that was freed, grown
  with `xreallocarray()` or handed to a library that owns it now, a
  field of a parsed document after its body is gone, a second free on
  an error path, a `__cleanup` that runs before the last use. In BPF, a
  map value used after its entry was deleted or replaced, a pointer
  kept across a call that sleeps or leaves the RCU read section, arena
  memory another run frees (the `bpf-concurrency` skill).
- **Logic errors.** The check that is there and wrong: an inverted or
  off-by-one condition, `<` for `<=`, the wrong variable after a copy,
  a `switch` whose default allows, a prefix compared where the whole
  must match, a mask a bit off, checks in an order that keeps the
  second from running, a hook that returns the wrong sign or returns
  before its check. No tool finds these: say from the threat model and
  the callers what the function must do, then read whether it does.
- **Hook logic.** In the programs of `bpf/`: a failed read, a helper
  error, storage that cannot be allocated or a bounded walk that gives
  up, taken as allow; a hook whose return the kernel ignores relied on
  to refuse; a decision on user memory the kernel reads again; a map
  the design takes as fixed that a program can still write
  (`BPF_F_RDONLY_PROG`); state shared by runs that interleave, as the
  `bpf-concurrency` skill describes.
- **Measurement gaps.** A state change without its register extend, in
  another order, without domain separation, outside the register lock,
  or a record the verifier folds that no digest covers.
- **State windows.** A control that holds in the running state and not
  around it: before `init` attaches the gates (T6), between a load's
  pins and its extend, with a config selection pending (T12), after a
  failed `init` (U11, U16), after a revocation.
- **Sibling paths.** One effect by several routes: `upatch load`, boot
  restore, `upatch reconcile`, `bpm upgrade` and a revocation purge all
  change what is loaded or attached. Compare their checks for
  equivalence, not presence, and read each undo and error path as
  closely as its success.
- **Self-report trusted.** A verifier check on a field of the target's
  own account. A check that trusts what the target wrote about itself is
  no check.
- **Encoding ambiguity.** Two inputs that hash or sign the same: lengths
  not bound, hex case, separators, names truncated rather than refused.
  Or one input that two readers take differently: a duplicate key,
  member or section, shirudo's reading of a loader, BTF or tar against
  the kernel's or the operator's, padding or uninitialized bytes in
  what is hashed, signed or measured.
- **Bytes as strings.** Bytes that came with a length handed to a
  function that reads up to a terminator: `strcmp()`, `strlen()`,
  `strchr()`, `strstr()`, `strcspn()`, `strtok_r()`, a `%s`. For each
  place bytes enter, settle where the length comes from and whether a
  terminator is written before such a function runs, an over-read
  otherwise; what a NUL among the bytes does, refused or the string
  ends short, so that a digest or a signature covers bytes a compare
  never saw, a name on disk is not the name checked, or the kernel
  reads what shirudo did not; whether a fixed-size field is compared
  whole or up to a terminator that need not be there; whether a digest
  over several strings delimits or counts each; whether a length is
  narrowed before it bounds a copy or a compare; and whether a name is
  checked once before it is printed, hashed or put in a path. Bytes
  become a string through `span_to_str()`, `read_text_line()` or
  `json_parse()`, and a field through the `memchr()` of its parser:
  look for the reader that has none of them, and for a strict JSON
  writer given text nobody checked, which fails the whole document. The
  `read_unterminated` and `file_as_string` rules match a buffer a read
  left unterminated and a file searched as a string; a field whose NUL
  another function checked and a copy terminated by hand they do not
  see.
- **Hook bypass.** Another syscall reaching what a hook refuses: both
  rename endpoints, hard links, truncate, xattrs, idmapped mounts, a
  descriptor opened before the mark, `bool kernel` misread. Take the
  routes from the kernel source: the callers of `security_<hook>()` and
  what reaches the effect past them, not what you remember of them.
- **Unattended availability.** A registry or package that loops, wedges
  or fills the disk on every timer run, or holds the register lock so
  that every upatch command refuses. A crash of a one-shot command on
  its own operator's input is not this.
- **Text and secrets.** Unverified names printed without
  `text_sanitize()`; key material not cleared with `memzero_explicit()`
  on every path out, or compared without `memneq_explicit()`; secrets in
  logs; what G8 keeps from a task without authority leaving in a log
  line, `status` output, an error message or an export.
- **Environment and exec.** The target runs no subprocess. Look for
  variables, search paths and libraries a process with runtime authority
  takes from root (U3), and at what else an exec keeps for it: open
  descriptors, the working and root directory, resource limits, signal
  state, namespaces.
- **Linked code.** The target links OpenSSL, libcurl, tpm2-tss, libelf,
  zlib, zstd, LuaJIT and libbpf statically, at the versions
  `Makefile.target-deps`, `vendor/libbpf` and the build host give
  (`.github/scripts/gen-sbom.sh` lists them). A published flaw in one
  is a finding when the build keeps the affected code and an
  adversary's bytes reach it. The proofs stop at these libraries, and a
  sanitizer sees only what was built with it.

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
