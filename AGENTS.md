# AGENTS.md

Guidance for coding agents (Claude Code, Codex, and others) working in
this repository. The code and `Documentation/` are authoritative for
what shirudo does; this file holds the rules and the reasoning that are
not visible from the code.

## Capability requirement

shirudo is a security-critical BPF security platform. A subtle error in
signature verification, LSM hook policy, TPM measurement, the pre-flight
tamper check or the signed-loader artifact format silently invalidates
the trust model while the code still looks correct, and it ships to
fleets and embedded devices that are hard to patch. Work here only with
a frontier-class model at its highest reasoning effort (for Claude
Code: Mythos or newer at high or extended effort; Codex: the strongest
available model at high reasoning). Lower tiers may read and answer
questions but must decline to change anything and say why. Before
changing security-relevant code, read
`Documentation/internals/architecture.rst` and
`Documentation/security/threat-model.rst`.

## What shirudo is

A BPF security platform that locks down the `bpf()` syscall so only signed in-kernel
BPF loader programs can install BPF code, create maps or attach links,
even for `CAP_SYS_ADMIN`. One plain-C binary serves two roles, chosen by
what is present on the machine, never by separate builds:

- the *operator* holds the private ML-DSA-87 signing key and produces
  signed `.upatch` artifacts (`shirudo build`, `shirudo bpm build`), and
  publishes packages (`shirudo bpm push`, `shirudo bpm tree append`);
- the *target* holds only the public certificate in a sealed kernel
  keyring plus a per-boot TPM2 measurement register bound from the
  initrd under PCRs 9 and 11 and anchored in PCR 9, verifies every
  load, emits TPM-signed evidence on request
  (`shirudo attest`) and is agentless: no daemon, no listening socket,
  every operation is a one-shot CLI invocation run locally or by the
  systemd timers that pull packages (`bpm repo update`, `bpm upgrade`,
  `bpm tree sync`) and export status (OTLP). The operator verifies that
  evidence offline (`shirudo attest verify`, `shirudo attest predict`).

Delivery is pull-based: the operator publishes to an OCI registry, the
target fetches and verifies. shirudo has no push transport, no SSH
integration and no fleet state; do not reintroduce the removed fleet,
remote-management or transport layers.

## Where things are documented

| Path | Purpose |
|---|---|
| `Documentation/security/threat-model.rst` | Authoritative security design: assumptions, assets, trust boundaries, adversaries, threats with the hooks, counters and tests behind each, residual risks, threats to resolve, deferred mitigations. Consult before touching any security-relevant path. |
| `Documentation/internals/` | How shirudo works and why: architecture, signed loader path, enforcement in the kernel (every LSM hook), seal labels and task marks, boot from initrd to root, measurement register and attestation, config images, kernel interfaces, carried kernel patches, design decisions. Read the page for a mechanism before changing it. |
| `Documentation/concepts/` | The concepts and the background mechanisms shirudo builds on (BPF, CO-RE, BPF signing, the BPF LSM, keyrings, xattrs, dm-verity, initrd, boot, TPM, post-quantum cryptography, OCI, OpenTelemetry, LuaJIT) and the glossary. |
| `Documentation/start/` | Quickstart, installation and short guides. |
| `Documentation/operate/` | Operator how-tos: system requirements, deployment, boot integration, keys, attestation, reading status, telemetry, upgrades, recovery, troubleshooting, incident response, hardening. |
| `Documentation/upatches/` | Authoring and shipping upatches: attach kinds, maps and serializers, decoders, the Beefile, publishing, debugging a failed load. |
| `Documentation/reference/` | Every command (`reference/cli/`), the formats and settings (`reference/formats/`, including the `.upatch` container), failure categories and exit status, files, units, environment variables, the cheat sheet. |
| `Documentation/contribute/` | Developer guide, test tiers and the test VM (read `testing.rst` before adding or moving a test), test coverage, the kernel coding style, commits and sign-off (read `contributing.rst` before crafting a commit), and the documentation style guide `writing-docs.rst`. |

The kernel side of the signing design is the kernel's own
`Documentation/bpf/signing.rst`; `bpf_prog_verify_signature()` runs
inside the verifier, after the `bpf` LSM hook and before the
`bpf_prog_load` one, and `attr.keyring_id` is a key serial, not a name.

The documentation is kept in sync with the code. A change to behavior
updates the pages that describe it in the same commit: a command, an
option, a message, an exit status, a failure category, a tamper
counter, an LSM hook, a file, a unit, a format, a threat or a test
that is added, changed or removed is added, changed or removed in
`Documentation/` too, and a residual risk or threat to resolve that a
change closes leaves the threat model. A page that no longer matches
the code is a bug, whichever of the two is wrong.
`.github/scripts/check-docs.sh` catches the names it can; the prose is
the author's to check.

New documentation extends an existing page or adds one to its section's
toctree, and follows `Documentation/contribute/documentation/writing-docs.rst`. Only
what concerns the project as a whole goes in the top-level directory
(`README.md`, `CONTRIBUTING.md`, `SECURITY.md` and their kind). No
README, plan or notes file goes beside the code; the exceptions are
`vendor/libbpf/README.md`, which belongs to the vendored copy, and a
package's `README.md` under `upatches/`, which `bpm build` ships in the
package for `bpm info`.

## Coding conventions

- **Plain C.** Userspace and BPF both. No C++.
- **Zero-initialise with `= {}`, not `= {0}`.** The empty-initializer
  form is the kernel convention (a GNU extension shirudo's `-std=gnu11`
  accepts). Use it for every struct/array/union zero-init. When adding
  new code, write `= {}`.
- **Spell fixed-width integers the kernel's way**: `__u8`, `__u16`,
  `__u32`, `__u64` and `__s8` to `__s64`, from `<shirudo/types.h>`,
  which `<shirudo/misc.h>` includes, in userspace and `vmlinux.h` in
  BPF, not `uint32_t` and its kin nor `unsigned int`, `unsigned long`
  and the like. `__u64` is `unsigned long long`, so it prints with
  `%llu`, and `ptr_to_u64()` turns a pointer into the `__u64` the bpf()
  ABI carries. A library interface that takes another type keeps it,
  and BPF programs spell hook arguments as the kernel's prototypes do.
  `<shirudo/misc.h>` poisons `uint8_t` to `int64_t`, so a system header
  that uses them, `<netinet/in.h>`, `<elf.h>` or one of OpenSSL's or
  tpm2-tss's, goes above the first shirudo header. `check-style.sh`
  rejects `uint32_t` and its kin everywhere and `unsigned char`,
  `short`, `int` and `long` in userspace, less the files it names.
- **Parse numbers with `parse_u64()`, `parse_s64()` and `parse_x64()`**
  from `<shirudo/string.h>`, and find where one ends with `digits()`:
  they take a length, read nothing past it and refuse a sign, blank or
  base prefix. `<shirudo/string.h>` poisons `strtoul()` and its kin and
  `atoi()`, and `check-style.sh` rejects them outside `testing/`.
- **Check size and length arithmetic with the helpers of
  `<shirudo/overflow.h>`**: `check_add_overflow()`,
  `check_sub_overflow()` and `check_mul_overflow()` say whether the
  result fits the destination, and `size_add()`, `size_sub()`,
  `size_mul()` and `struct_size()` stick at `SIZE_MAX`, so the
  allocation they size fails. Not `a > SIZE_MAX - b` or
  `n > SIZE_MAX / size` by hand.
- **Copy strings with `strscpy()` and format into a fixed buffer with
  `strsprintf()`**, or `vstrsprintf()` from a `va_list`, all from
  `<shirudo/string.h>`: `strscpy()` always terminates and returns
  `-E2BIG` when it cut, which a caller checks wherever a cut path or name
  would mean a different one, and `strsprintf()` returns `-E2BIG` with
  the buffer left empty rather than a cut value, and its result must be
  used: a path or value is refused, a helper that formats display text
  returns it, and status shows `"?"` for a field it cannot fill. Bytes
  are hex-encoded with `hex_encode()` and constant text is copied, not
  formatted. `<shirudo/string.h>` poisons `strcpy()`,
  `strncpy()` and their kin and `sprintf()`, `snprintf()` and their
  `va_list` forms, which only `util/string.c` and the `xasprintf()` of
  `util/malloc.c` call, and `check-style.sh` rejects them outside
  `testing/`.
- **Name a return code `ret`**, as the kernel does, and an errno from a
  callee that a function keeps beside the value it returns `err`.
- **No `(void)` casts.** A function whose result a caller must not
  drop is `__must_check`, and every call checks it; a fuzz target holds
  what it parses to an invariant and `abort()`s when it breaks. A result
  that callers may ignore belongs to a function that is not
  `__must_check`. Unused parameters need nothing, as every build passes
  `-Wno-unused-parameter`, and an unused variable is removed.
- **Do not prefix internal names with `shirudo_` or `SHIRUDO_`.** A
  function or macro of shirudo's own code is named after what it is,
  `upatch_open()` and `NV_INDEX`, as in the kernel. The prefix stays
  where the name leaves the code: include guards, the BPF map, program
  and pin names a loader or a pin path finds, the environment variables,
  and a name that would otherwise collide, such as `shirudo_trunc()`
  beside libm's `trunc()`.
- **Declare locals in reverse-Christmas-tree order** (the netdev
  convention): longest declaration line first, shortest last. Group
  declarations that have no initializer dependency and sort them by
  descending line length; a declaration whose initializer references an
  earlier local must stay after it (correctness wins over the sort).
  Apply this whenever you add or touch a declaration block.
- **Linux kernel coding style**
  (`Documentation/contribute/code/coding-style.rst` — the kernel's own
  coding-style.rst, copied into this tree). Tabs (8-wide), 80-col soft
  limit and 100-col hard limit (checkpatch), K&R braces, no spaces
  inside parens.
  Apply to userspace too — eases review. **Comments are rare and
  follow §8** (see below): at the function head, not inside the
  body; file headers are SPDX + Copyright + at most one line of
  purpose, never multi-paragraph descriptions.
- **Multi-line comments**: the opening `/*` and closing `*/` each
  go on their own line, with every content line beginning with ` *`.
  Single-line comments (`/* foo */`) and trailing field annotations
  (`int x; /* sticky */`) are fine. WRONG:
  ```
  /* Foo bar
   * baz quux. */
  ```
  RIGHT:
  ```
  /*
   * Foo bar
   * baz quux.
   */
  ```
  This applies to every block comment — function-head doc comments,
  TODO blocks, struct-internal explanations, multi-line trailing
  comments inside a function body. The rule mirrors the kernel
  example in `Documentation/contribute/code/coding-style.rst` §8.
- **`//` is for SPDX only.** Per the kernel convention, .c files
  use `// SPDX-License-Identifier: …` and nothing else `//`-style;
  .h files use `/* SPDX-License-Identifier: … */` and nothing else
  `//`-style. Every other comment is `/* */`.
- **License: BSD-2-Clause** for userspace. The BPF program must declare
  `char _license[] SEC("license") = "Dual BSD/GPL";` (the LSM hook framework
  rejects non-GPL-compatible BPF), and every file compiled into a BPF
  object, including the headers it includes and the package's Lua
  decoders, carries `SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause`,
  the kernel's form of the dual licence, matching the Beefile.
- **No emojis** anywhere — code, comments, commit messages, logs.
- **Comments are rare.** Add one only for what is non-obvious and cannot
  be inferred from the code: a hidden invariant, a kernel or library
  quirk, why the code takes the less obvious path. It explains *why*,
  never *what*: no comment that restates a function, parameter or field
  name, the return value, or the messages the code prints. No
  multi-paragraph docstrings. No "added for issue X" or "used by Y" —
  those go in commit messages.

## Commits

`Documentation/contribute/code/contributing.rst` is the kernel's process
applied here and is the reference for every commit an agent prepares: a
subject of the form `area: imperative summary`, a body that explains why
before what, and the `Co-developed-by`, `Fixes`, `Reported-by`,
`Suggested-by`, `Tested-by`, `Reviewed-by`, `Acked-by` and `Cc` tags
used as the kernel uses them. Every commit needs a `Signed-off-by:` from
a real identity, and only a person can give one: an agent never adds a
sign-off, on its own or anyone else's behalf, and leaves that line to
the human who reviews and submits the work. One logical change per
commit, each one building and passing on its own.

## Invariants that are easy to break

Each of these is enforced by the design, not by a compiler. Breaking
one usually still compiles and passes tests.

- **No target subprocesses, no daemons.** Target operations in the core
  `shirudo` binary use linked libraries and kernel APIs. Operator commands
  dispatch to the separate `shirudo-build` helper. That helper signs
  in-process, executes `clang` for BPF compilation and delegates image
  generation to Bash scripts using standard `veritysetup`. Offline verification
  authenticates the root in the helper before invoking `veritysetup verify`. Those
  external tools are operator-only dependencies. Target image preflight
  checks the standard verity superblock and root. The kernel verifies config
  signatures through its dm-verity trust path; runtime acceptance requires
  the exact UKI root. A strict read-only mapping is read completely before
  parsing contents or extending the activation PCR. Config signatures cover
  exactly the 64 lowercase ASCII root bytes and never authorize executables.
  Do not add a target shell-out or a custom userspace verity hash-tree
  implementation.
- **Operator code does not ship to targets.** Signing (`util/sign.c`)
  and the package builder and publisher (`tools/shirudo-build/`) are
  linked only into `shirudo-build`. The core binary only dispatches.
- **The signature-gated `BPF_PROG_LOAD` is the upatch trust boundary.**
  Every signed load and unload directive goes through the same load path.
  The embedded LSM bootstrap loads during `init`, before its admission
  gates attach. Production deployments authenticate it through the initrd.
  Authorized shirudo tasks may attach, pin and run the signed-loader data-map
  pattern, because none of those can introduce unsigned code; detach,
  update and corruption of BPF objects from userspace are denied by the
  LSM. In the `lsm/bpf` hook the `bool kernel` argument is the
  discriminator: calls from inside a signed loader are allowed,
  userspace calls are filtered.
- **The operator never touches the kernel keyring or the TPM; the
  target never touches the private key.**
- **The bpf keyring is the trust anchor.** Every target requires the kernel
  `.bpf` keyring. Boot with `bpf.keyring_unsealed=1`; init verifies the runtime
  and signed config, enrolls the initial certificate and vouched boot signer
  set, then seals the ring. No user-keyring staging is supported. The frozen
  record and BPF admission checks enforce that ring. Live signed config can
  revoke an enrolled key and purge its upatches, but cannot enroll a new key.
  Target-local key changes are refused. BPF upatches always require signed
  loaders; a signed config does not authorize unsigned BPF.
- **The operator is stateless.** It writes only the keypair (`genkey`)
  and the artifacts or reports the caller names. No hidden caches,
  state files, logs or staging directories; `--expect-chain` comes
  from the caller or from `shirudo attest predict`.
- **upatch state changes extend the TPM measurement register**
  with a domain-separated tag, in deterministic order. Commands refuse
  on drift (`tampered`) rather than retrying. Boot restore is exactly one
  register event and a re-run of `init` adds none. A load stopped
  between its pins and its extend leaves pins without a record: `status`
  reports them (`UpatchesMeasured`) and the next upatch command undoes
  them under the register lock, which a load or an unload holds from
  before it touches the pins to its append. `init` restores only an
  archive whose load the eventlog records without a later unload; a
  labeled archive root brings back is reported and removed, never
  restored. The register follows
  systemd's NvPCR construction (`util/chain.c`): an NV extend index that
  clears at TPM reset, a first write only possible while PCRs 9 and 11
  hold the values the policy was computed from, which is why `init`
  runs from the initrd before `leave-initrd` moves PCR 11, and the
  index name extended into PCR 9 right after it. Do not reintroduce a
  persistent index or
  an auth value derived from the certificate; the upatch tree measures
  into the same register. A TPM 2.0 is mandatory; there is no
  unmeasured mode. Image config activation extends the separate PCR
  selected in authenticated bootstrap settings. A durable pending selection
  requires manual reboot after any interruption; shirudo never reboots the
  node automatically. There is no same-boot recovery or
  ambiguous-extension retry. Trusted startup verifies that selection and
  records a fresh BOOT event before completing initialization.
- **Evidence is signed by the TPM, verified by the operator.** The
  attestation key is a fixed-template primary under the endorsement
  hierarchy, pinned by name and tied to the endorsement key by
  credential activation (`shirudo attest challenge` computes the
  credential in software on the operator, `attest --challenge`
  activates it on the target); `shirudo attest verify` recomputes the
  register's public area from the recorded PCR binding and the expected
  value from the certificate and the artifacts. A check that trusts a
  value the target wrote about itself is not a check.
- **Pin the bpf_link before anything else fallible** in `shirudo init`,
  or a crash leaves an attached, unowned link that the kernel detaches.
- **init runs twice in production.** The authenticated systemd initrd binds
  persistent state writable, verifies runtime and config, enrolls and seals the
  `.bpf` and `.dm-verity` keyrings, labels state, attaches all guards, restores
  signed upatches and binds the register. Mounts and pins live under `/run`
  across switch-root. The root service uses the verified runtime and adopts
  the pending initrd event. Missing images or settings are errors. No mode
  selector, executable inode identity or unsealed fallback may be added.
- **Seal labels mark targets, not caller authority.** Only successful exec
  from the authenticated runtime grants the committed task mark. Fork inherits
  it, successful exec re-evaluates it and failed exec preserves it. Writable
  state retains its seal xattrs; runtime and config files use dm-verity. Only
  an authorized caller may set or remove the exact seal xattr. Both rename
  endpoints, write open, unlink, setattr and xattr changes are checked. There
  is no executable replacement exception.
  Label read errors require authority except ENODATA and EOPNOTSUPP; an
  EACCES or EPERM, which root brings about with an idmapped mount or an
  ACL, requires authority when the inode or the directory the operation
  changes carries a mark; scratch allocation failure also requires
  authority. The seal marks what it labels at creation, what shirudo
  opens and what anyone opens for writing or as a directory, and
  refreshes a directory's mark in every entry hook from the label it
  reads there (carried kernel patches 0003 and 0004 make those hooks
  sleepable and `dentry->d_parent` trusted), so that
  `inode_init_security`, which has no dentry, labels the new inode from
  it: the marks are a cache, never the decision. A sealed inode cannot
  be hard-linked by a task without authority. Existing writable
  descriptors and mappings are not revoked.
- **Single shirudo instance per host.** Keyring name, private bpffs,
  `/var/lib/shirudo`, the `security.bpf.shirudo` xattr namespace and
  the NV index are single-tenant by design.
- **Kernel + shirudo is the target TCB.** Ask of every change whether it
  grows the TCB; the agentless design exists to keep it minimal.
- **Bleeding-edge kernel and toolchain only.** The signed-loader ABI
  described in `Documentation/operate/plan/system-requirements.rst` and
  current clang/LLVM, release 23, are hard prerequisites. Every CI job
  installs it with `.github/scripts/install-clang.sh`; verify compiler
  behavior with it, not an older host clang. Development trees can
  expose that ABI before the corresponding release number changes; use a
  verified commit, not just `uname`, to identify the tested kernel. No
  legacy-kernel fallback paths; a missing kernel feature fails the build
  or the load. x86-64, arm64 and riscv64 are the supported architectures.
- **BPF is CO-RE.** Hard-coded struct offsets sign fine and fail on the
  wrong kernel, where the verifier rejects the payload
  (`verifier_rejected`).
- **BPF targets instruction set v4.** Every `clang -target bpf` in the
  tree passes `-mcpu=v4`: the upatch build, the embedded objects, the
  configure probe and the tests. Not `-mcpu=probe`, which describes the
  build host's kernel, not the targets'. Each compile also passes
  `-fno-jump-tables`: clang 23 otherwise turns a dense `switch` into a
  table in `.rodata` read at an offset the verifier cannot bound, and
  the program is refused. upatches are therefore compiled
  with the full BPF instruction set: load-acquire and store-release,
  sign-extending loads and moves, and signed division and modulo are all
  there, so write the code that needs them directly and do not work
  around their absence.
- **upatch state lives in BPF arenas where possible.** A upatch that
  accumulates records keeps them in its one `BPF_MAP_TYPE_ARENA` map and
  ships a `shirudo_serialize__<map>` program that walks them; hash and
  array maps are for what cannot live in an arena: task and socket
  state, per-CPU counters and scratch, lookup keys the kernel owns, and
  the serializer output. An arena gives one consistent snapshot, memory
  the serializer can reset between exports, and an overflow count the
  record carries, where an element-by-element read of a plain map gives
  a torn view and a table that silently fills up.
  `upatches/kernel-obs/obs_table.h` is the template to instantiate.
- **Test the locking of complex upatch BPF code with blitmus.** Where
  programs on several CPUs share state through atomics, acquire and
  release, or a lock or lock-free structure built from them, write the
  pattern as a litmus test and run it with blitmus
  (https://github.com/puranjaymohan/blitmus) on x86-64, arm64 and
  riscv64: a pass on x86-64 says little about the other two. It covers
  `READ_ONCE()`, `WRITE_ONCE()`, acquire, release, full barriers and the
  add, exchange and compare-and-exchange atomics, not the or, and and
  xor atomics, `bpf_spin_lock()` or RCU.
  `Documentation/upatches/write/memory-consistency/blitmus.rst` shows how.
- **Write upatch BPF code for runs that interleave, and apply each fix
  only under the preemption model and program types its hazard needs**,
  never to every program by reflex. Runs on different CPUs at once exist
  on every kernel: update a value other CPUs share, of a map that is not
  per-CPU or in inode, socket or cgroup storage, with
  `__sync_fetch_and_add()` and its kin; insert a missing key with
  `BPF_NOEXIST` and look it up again on `-EEXIST`; read or copy a map
  value before deleting its entry, as the map hands the element to the
  next update at once; check every compare-and-swap result, as a failed
  one changes and orders nothing; publish a filled record with
  `__atomic_store_n(&p, v, __ATOMIC_RELEASE)` or a value-returning
  atomic, never `WRITE_ONCE()`, and read it through `READ_ONCE()` and an
  address dependency, or a load-acquire where the code compares the index
  with a constant first; expect writes that land in the half of a double
  buffer being drained, as BPF has no grace period; and read user memory
  once.

  A second run on one CPU before the first one ends depends on the
  kernel. `PREEMPT`, `PREEMPT_RT` and `PREEMPT_DYNAMIC`, the default and
  what distribution kernels use, bring preemptible RCU, and
  `PREEMPT_LAZY` on its own does not. Since 7.0 `PREEMPT_DYNAMIC` boots
  only `full` or `lazy`, not the `voluntary` distribution kernels used to
  boot, in which no task preempted a running program: do not carry that
  assumption over. With preemptible RCU another task can preempt most
  programs, and on every kernel `syscall` and sleepable ones. On every
  kernel a softirq can run on top of a run in a process, and `lsm`,
  `syscall`, `cgroup_skb`, `netfilter` and `uprobe.multi` programs have
  no guard against a second run of themselves, while `kprobe` and
  `kretprobe` programs never interleave with each other on a CPU and
  `fentry`, `fexit`, `fmod_ret` and `tp_btf` programs never with
  themselves. Only where such a second run can come is a per-CPU map
  value, or a slot picked by `bpf_get_smp_processor_id()`, shared between
  runs: keep scratch there in task storage where no program a softirq
  runs uses it (as the seal does), on the stack, or behind a busy flag
  taken with `__atomic_exchange_n()` and given back with a release store,
  and update a per-CPU counter there with an atomic. Elsewhere, such as a
  counter only one `kprobe` program updates, the plain form is right. A
  upatch whose correctness depends on the model says in its `README.md`
  which one it is written for, as kernel-obs does for the test VM's
  kernel, and its code is checked against that one. The test kernel is
  built with `PREEMPT_LAZY` alone, so the VM suite shows the preemption
  cases only for `syscall` and sleepable programs.

  The `bpf_` rules in `testing/coccinelle/` refuse these patterns within
  one function. No rule refuses per-CPU scratch, as whether it is a
  hazard depends on the kernel and the programs that share a map, which a
  rule cannot tell: review decides. A hazard spread over functions, or a
  file with its own token-pasting macros such as `obs_table.h`, needs
  review and blitmus.
  `Documentation/upatches/write/memory-consistency/hazards.rst` says
  where each hazard applies.
- **Plan for what an upatch program does not see.** The kernel skips
  `kprobe` and `kretprobe` runs while another one runs on the CPU or the
  CPU is in a `bpf()` map call, runs of an `fentry`, `fexit`, `fmod_ret`
  or `tp_btf` program already running there, and `kretprobe` returns
  beyond its instances, so a detector can miss what it looks for. Refuse
  an operation in an `lsm` program wherever a hook covers it, never in
  `fmod_ret`: a skipped `fmod_ret` run lets the call through, and a task
  can arrange the skip. An `lsm` program does not see what an LSM before
  it refused, and its hook runs before the operation, which can still
  fail. In a softirq the current task is whichever one was interrupted. A
  sleepable program walks RCU pointers under `bpf_rcu_read_lock()`. Check
  map update and delete results where a lost update matters, size LRU
  maps with room to spare, and read values userspace rewrites under
  `BPF_F_LOCK`. Prefer `lsm`, `tp_btf` and `fentry` to `kprobe`, which
  misses calls the compiler inlined.
  `Documentation/upatches/write/pitfalls.rst` explains each. When
  `shirudo build` starts accepting another attach kind, the same commit
  adds its run context to the table in `hazards.rst` and what it misses
  or cannot rely on to `pitfalls.rst`, so that agents writing upatches
  for it meet its hazards there.

## Memory, JSON and logging

- Keep tables off the stack: a frame past 128 KiB fails the build
  (`-Wframe-larger-than`). Allocate a table with `xcalloc()`, and mark
  a helper with a large buffer `noinline_for_stack` where inlining
  would add its frame to its caller's.
- Take the smaller or larger of two values with `min()` and `max()`,
  which refuse operands that compare differently as signed and
  unsigned; a constant compared with an unsigned value takes a `U`
  suffix. `min_t()` and `max_t()` cast, which can cut a value short, so
  they are for only what `min()` and `max()` refuse.
- Use the zeroing allocator in `util/malloc.{c,h}`: `xmalloc`/`xcalloc`
  return NULL on failure (never die), `xfree(ptr, size)` and
  `xstrfree` scrub before freeing. The libc allocators are poisoned
  project-wide; do not add exceptions, wrap in `util/malloc.c` instead.
  `xstrdup` is strlen-based, so never apply it to user, file or network
  input; use `xstrndup(s, bound)`. `xasprintf` formats into memory of
  the size needed, freed with `xstrfree`.
- Scrub a secret, a key, an auth value, a seed, a KDF output, a
  credential or a buffer that held one, with `memzero_explicit()` from
  `<shirudo/string.h>` on every path out of its scope, the error paths
  included. A `memset()` of memory nothing reads afterwards is a dead
  store the compiler drops; `explicit_bzero()` is poisoned in favor of
  the kernel's name. Compare such a value with `memneq_explicit()`
  from the same header, which reads every byte whatever the bytes
  before it held; `memcmp()` returns at the first difference.
- `util/json.{c,h}` is the only JSON code. Extend its schema
  definitions for new fields or documents; never open-code JSON bytes
  elsewhere.
- Logging is `syslog(3)` through `util/log.c` (`pr_info`, `pr_warn`,
  `pr_err`, `pr_audit`); journald picks it up. No `libsystemd`, no
  on-disk log of shirudo's own.

## Dependencies and licensing

- The binary links exactly `libc`, `libcrypto`/`libssl` (OpenSSL >= 3.5;
  ML-DSA-87 is the only signing algorithm, TLS is 1.3 with hybrid ML-KEM
  only), `libcurl`, `libtss2-esys` + `libtss2-tctildr`, `libelf`,
  `zlib`, `libluajit` and the vendored `libbpf`. A new library must be
  absolutely necessary, universally available, actively maintained,
  BSD-2-Clause compatible and load-bearing for one thing. `libsystemd`,
  `libsubcmd`, `libkeyutils`, `libcap` and any JSON/YAML/TOML parser
  are refused; whiteroom or open-code instead.
- Every line in the binary is fresh BSD-2-Clause or vendored from a
  permissive OR-branch with its SPDX header kept (`vendor/libbpf`,
  `util/sign.c`). Never copy or link GPL-2.0 code; study a pattern,
  then write it from scratch without the GPL source open.
- No kernel tree or submodule is needed to build: libbpf and the BPF
  UAPI headers live in `vendor/libbpf/` and `vmlinux.h` is generated
  into `vendor/linux/` from BTF. `make bpf-deps` refreshes the
  vendored copy and is run only when asked.

## Building, testing, packaging

- `make` builds the operator binary; `make shirudo-build` the helper;
  `make target` the fully static PIE target profile (`make target-deps`
  builds OpenSSL, libcurl and tpm2-tss from source first).
- A compiler warning fails every build the Makefiles drive, the BPF
  objects, vendored libbpf, test helpers and fuzz targets included;
  fix the warning rather than silence it. `WERROR=0` is for a compiler
  newer than the tree, while its new warnings get fixed.
- `make tests` (or `make -C testing`) runs every test, and is what CI runs;
  `make -C testing unit`, `ci-checks`, `functional` or `end2end` runs one
  tier, `unit/<suite>` or `functional/<family>` part of one. The target
  tests (`t?1??`) run as root in QEMU/swtpm VMs, one fresh VM per family;
  `VM=0` leaves them out, and `make tests VM=0
  SANITIZE=address,undefined` runs the rest under ASan and UBSan (CI does
  too). `make -C testing help` lists the suites and families.
- The target tests always boot the dm-verity runtime and signed
  config from a dracut initrd. CI runs that same required suite through
  `.github/scripts/tests.sh`; the old root-only installer suite is gone.
- `util/<m>.c` is unit tested by `testing/unit/<m>.c`: a change to a util
  function adds or updates its cases there. A shell test is named
  `t<F><K><NN>`, family, operator (0) or target (1), and order, and lives in
  its family's directory; `Documentation/contribute/testing/testing.rst` has the
  families.
- `make -C testing fuzz [FUZZ_SECONDS=60]` runs the libFuzzer targets in
  `testing/fuzz/` for the parsers of input from outside the host, under
  ASan and UBSan, on their seed corpora; CI runs them too. A parser that
  takes such input gets a target there.
- `make docs` renders the documentation with Sphinx in a container and
  serves it on 127.0.0.1:8000. `make -C Documentation check` renders it
  with every warning an error and runs `.github/scripts/check-docs.sh`,
  which checks the options, failure categories, tamper counters, hooks,
  tests and units the pages name against the tree. CI runs both on every
  push, so run the check after touching a document or one of those names
  in the code. It needs podman or docker; `DOCS_CONTAINER=0` uses a host
  Sphinx installed from `Documentation/requirements.txt`.
- `.github/scripts/check-spdx.sh` checks the SPDX tag of every tracked
  source against the licensing rules above: the form for the file type,
  the expression, the dual licence for everything a BPF object compiles
  and a Beefile ships. `.github/scripts/check-dco.sh <range>` checks
  that every commit has a one-line subject, a body beyond its tags and
  the author's sign-off from a real address: a noreply address or a
  `[bot]` is rejected as author, signer or co-developer.
  `.github/scripts/check-style.sh <range>` runs the kernel's
  checkpatch.pl in strict mode over the C each commit touches and over
  its message, with the userspace exceptions listed in the script, and
  rejects the netdev block-comment opener.
  `.github/scripts/check-sparse.sh` runs `make sparse`, sparse over the
  userspace sources, which fails on a little-endian or big-endian field
  read or written without `le32_to_cpu()`, `cpu_to_le32()` or their kin
  from `<shirudo/byteorder.h>`. `.github/scripts/check-coccinelle.sh`
  runs the semantic patches in `testing/coccinelle/`, each a pattern the
  tree is kept free of, and fails on any match; a pattern worth refusing
  for good gets a rule there, written from scratch or carried with its
  SPDX and copyright lines from a project that offers it with a
  BSD-2-Clause branch, with the tree fixed first. CI runs all five on
  every pull request,
  and `.github/scripts/build-commits.sh <range>` builds every commit of
  a pull request on its own; run them before handing work over.
- Shell that a workflow runs lives in `.github/scripts/`, not inline in
  the workflow file.
- `make -C packaging bindeb-pkg`, `make -C packaging binrpm-pkg` and `make -C packaging bintar-pkg` build the
  distribution packages. The target package is fully static PIE
  and portable; the operator package links the host's shared libraries
  and is built on the distribution it is for (`PKG_ROLES=operator`),
  against a bpf-next `vmlinux.h` (`BPF_VMLINUX_H=`). Package targets
  start from `make clean`.
- When a checkout is used in place of an installed operator package,
  `SHIRUDO_BUILD=<path>` names the helper, or put
  `tools/shirudo-build` and the checkout root on `PATH`.

## Out of scope

Do not propose features in these areas; the design delegates them:

- Transport and remote access: delivery is pull-based from OCI
  registries; there is no push channel, no SSH integration and no
  fleet orchestration. How an administrator reaches a target is not
  shirudo's concern.
- Audit and log retention: journald's job. The eventlog is append-only
  and unbounded by design; the register itself is per boot.
- Operator-host and on-disk binary integrity: signed packages, IMA,
  dm-verity, measured boot.
- Kernel hardening and TPM hardware attacks: trusted components.

Deferred work that is in scope is listed under deferred mitigations and
threats to resolve in `Documentation/security/threat-model.rst`.
