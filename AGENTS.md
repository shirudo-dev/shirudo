# AGENTS.md

Guidance for coding agents (Claude Code, Codex, and others) working in
this repository. The code and `Documentation/` are authoritative for
what shirudo does; this file holds the rules and the reasoning that are
not visible from the code.

## Before you write code

Read `.agents/skills/coding/SKILL.md` and follow it before you write,
change or review any C in this tree, userspace, BPF, tests and tools
alike, and before you write the commit message of such a change. It is
how code here is written, with
`Documentation/contribute/code/coding-style.rst` that it builds on.
Claude Code loads it as the `coding` skill, Codex from `.agents/skills/`,
and an agent that does not load skills reads the file.

Work another skill covers loads that skill as well:

- `testing` for tests
- `proofs` for proofs
- `docs` for documentation
- `upatch` for a upatch

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
  every operation is a one-shot CLI invocation run locally, by systemd
  when udev reports a new network device (`upatch reconcile`), or by the
  systemd timers that pull packages (`bpm repo update`, `bpm upgrade`,
  `bpm tree sync`) and export status (OTLP). The operator verifies that
  evidence offline (`shirudo attest verify`, `shirudo attest predict`).

Delivery is pull-based: the operator publishes to an OCI registry, the
target fetches and verifies. shirudo has no push transport, no SSH
integration and no fleet state; do not reintroduce the removed fleet,
remote-management or transport layers.

## Where things are documented

Before changing security-relevant code, read
`Documentation/internals/architecture.rst` and
`Documentation/security/threat-model.rst`. An audit of the tree or of a
change, and a check of whether a reported issue is real, follow the
`security-audit` skill.

| Path | Purpose |
|---|---|
| `Documentation/security/threat-model.rst` | Authoritative security design: assumptions, assets, trust boundaries, adversaries, threats with the hooks, counters and tests behind each, residual risks, threats to resolve, deferred mitigations. Consult before touching any security-relevant path. |
| `Documentation/internals/` | How shirudo works and why: architecture, signed loader path, enforcement in the kernel (every LSM hook), seal labels and task marks, boot from initrd to root, measurement register and attestation, config images, kernel interfaces, carried kernel patches, design decisions. Read the page for a mechanism before changing it. |
| `Documentation/concepts/` | The concepts and the background mechanisms shirudo builds on (BPF, CO-RE, BPF signing, the BPF LSM, BPF trampolines with `fentry`, `fexit` and `fmod_ret`, keyrings, xattrs, dm-verity, initrd, boot, TPM, post-quantum cryptography, OCI, OpenTelemetry, LuaJIT) and the glossary. |
| `Documentation/start/` | Quickstart, installation and short guides. |
| `Documentation/operate/` | Operator how-tos: system requirements, deployment, boot integration, keys, attestation, reading status, telemetry, upgrades, recovery, troubleshooting, incident response, hardening. `operate/backend/` describes the example backend of `tools/backend/`: its ClickHouse tables, node status and exposure, the jobs that load it, and `tools/xtop`. |
| `Documentation/upatches/` | Authoring and shipping upatches: attach kinds, maps and serializers, decoders, the Beefile, publishing, debugging a failed load. |
| `Documentation/reference/` | Every command (`reference/cli/`), the formats (`reference/formats/`, including the `.upatch` container), the settings (`configuration.rst`), the eventlog, failure categories and exit status, files, units, environment variables, the cheat sheet. |
| `Documentation/contribute/` | Developer guide, test tiers and the test VM (read `testing.rst` before adding or moving a test), test coverage, the kernel coding style, commits and sign-off (read `contributing.rst` before crafting a commit), and the documentation style guide `writing-docs.rst`. |
| `.agents/skills/` | Skills for coding agents in the `SKILL.md` format of agentskills.io, which Codex reads there and Claude Code through the `.claude/skills` link: `coding` writes C in the tree's style, grows `util/` and writes its commit messages, `testing` runs the test tiers and the test VM, `pre-submit` the checks CI runs on a series, `upatch` writes for the target's preemption model and a low cost, builds, packages and publishes an upatch, `bpf-concurrency` checks upatch code whose runs share state, `bpf-coccinelle` runs and extends the Coccinelle rules for it, `docs` finds and checks the pages a change touches, `fuzz-target` adds a libFuzzer target for a parser, `proofs` runs and writes the CBMC and Lean 4 proofs, `security-audit` audits the tree against the threat model, and the threat model and the proofs against the tree. |

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
the author's to check. The `docs` skill lists the pages each kind of
change touches and how to check them. The skills in `.agents/skills/`
name commands, make targets, options, files, scripts and rules as well:
a change to one of those checks the skills that mention it (`git grep
-n '<name>' .agents/skills`) and updates them in the same commit, and a
skill that no longer matches the tree is a bug like a page.

The proofs under `testing/proofs/` follow the code the same way. A
change to a file or function a CBMC harness includes or reaches (`git
grep -n '<file>.c\|<function>' testing/proofs/cbmc`), or to an algorithm
a Lean 4 model of `testing/proofs/lean4/` follows, adapts the harness or
the model in the same commit, with its line in `proofs.list` and its row
in `Documentation/contribute/testing/proof-coverage.rst`, and runs the
proofs it touches (`make proofs-cbmc CHANGED=<range>` picks them), as
CI runs them only once the change is on main. A proof that no longer
matches the code, or no longer holds, is a security bug: a threat's
fact box or a coverage row then claims an assurance the tree does not
have.
Proofs must not add runtime state used only to carry proof bookkeeping.
Derive the value from observable state in the harness, or state the
invariant directly, so production code retains only state needed at
runtime.

New documentation extends an existing page or adds one to its section's
toctree, and follows `Documentation/contribute/documentation/writing-docs.rst`. Only
what concerns the project as a whole goes in the top-level directory
(`README.md`, `CONTRIBUTING.md`, `SECURITY.md` and their kind). No
README, plan or notes file goes beside the code; the exceptions are
`vendor/libbpf/README.md`, which belongs to the vendored copy, and a
package's `README.md` under `upatches/`, which `bpm build` ships in the
package for `bpm info`.

## Coding conventions

C follows the kernel coding style,
`Documentation/contribute/code/coding-style.rst`, in userspace and BPF
alike. The `coding` skill gives these conventions with their reasons,
the helpers to use and the commit message that carries a change:
`.agents/skills/coding/SKILL.md` is the reference, and the "Before you
write code" section above has you load and follow it.

Coding conventions, helpers, patterns, and commit message format belong
in the `coding` skill, not here. This file documents architecture,
invariants, and project policies; the skill documents how to write C.

## Commits

Every commit follows `Documentation/contribute/code/contributing.rst` and
the commit message format in the `coding` skill. One logical change per
commit, each one building and passing on its own.

An agent never adds a `Signed-off-by:`, on its own or anyone else's
behalf: only a person can give one, and that line is left to the human
who reviews and submits the work.

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
  reports them (`UpatchesMeasured`) and the next upatch load or unload undoes
  them, or refuses when it cannot, under the register lock, which a
  load or an unload holds from before it touches the pins to its
  append, and a purge from its archive read until its pins and archive
  are gone. `init` restores only an
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
- **A map no BPF program writes is created with `BPF_F_RDONLY_PROG`.**
  `BPF_MAP_FREEZE` only blocks the syscall side; without the flag a BPF
  program could still write the map's value through a lookup's return
  pointer, and the verifier would allow it. `shirudo_bpffs_sb` carries
  the flag for that reason. A map a BPF program writes, even once
  (`shirudo_mnt_rec`, the task, socket and inode storage maps,
  `shirudo_tamper`, `shirudo_integrity`, `shirudo_devices`, upatch
  state), does not take it.
  A map added later that fits the no-BPF-write criterion takes the flag
  from the commit that adds it; a map that stops fitting it drops the
  flag in the same commit that adds the write.
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
- **BPF is CO-RE, built for instruction set v4.** Hard-coded struct
  offsets sign fine and fail on the wrong kernel (`verifier_rejected`).
  Every `clang -target bpf` in the tree passes `-mcpu=v4`, not
  `-mcpu=probe`, which describes the build host's kernel, and
  `-fno-jump-tables`, without which clang 23 turns a dense `switch` into
  a `.rodata` table the verifier refuses. upatch code uses the v4
  instructions directly rather than working around their absence.
- **upatch state lives in BPF arenas where possible.** The records a
  upatch accumulates go in its one `BPF_MAP_TYPE_ARENA` map, with a
  `shirudo_serialize__<map>` program that walks them: one consistent
  snapshot and an overflow count, where a plain map gives a torn view
  and a table that silently fills up. Hash and array maps hold what
  cannot live there. `upatches/kernel-obs/obs_table.h` is the template.
- **upatch BPF code is written for runs that interleave and runs the
  kernel skips.**
  `Documentation/upatches/write/memory-consistency/hazards.rst` says
  which hazard applies under which preemption model and program type,
  and each fix goes only where its hazard applies;
  `Documentation/upatches/write/pitfalls.rst` covers what a program
  does not see, and an operation is refused in an `lsm` program
  wherever a hook covers it, in `fmod_ret` only where none does.
  Ordering between CPUs is tested with blitmus on x86-64,
  arm64 and riscv64. The `bpf-concurrency` and `bpf-coccinelle` skills
  give the procedure. When `shirudo build` starts accepting another
  attach kind, the same commit adds its run context to the table in
  `hazards.rst` and what it misses to `pitfalls.rst`.

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

- `make` builds the operator binary, `make shirudo-build` the helper,
  `make quote-check` the backend's quote checker `shirudo-quote-check`,
  a static PIE in either profile,
  and `make target` the fully static PIE target profile (`make target-deps`
  builds OpenSSL, libcurl and tpm2-tss from source first). A checkout
  used in place of an installed operator package names the helper with
  `SHIRUDO_BUILD=<path>`.
- A compiler warning fails every build; fix it rather than silence it.
  Validate C changes, test code included, with GCC and with clang 23,
  `make -B` when switching `CC`.
- `make tests` runs every test as CI does. `util/<m>.c` is unit tested
  by `testing/unit/<m>.c`, a parser of input from outside the host has a
  fuzz target, and a shell test `t<F><K><NN>` lives in its family's
  directory (`Documentation/contribute/testing/testing.rst`). The
  `testing` and `fuzz-target` skills say how to run and add them. Its
  last tier is the SQL tests of `tools/backend`, which need docker or
  podman (`BACKEND=0` leaves them out). The tests of xtop are not part
  of it: `make -C tools/xtop tests`, which needs bun, runs them.
- `make proofs` runs the CBMC proofs of `testing/proofs/cbmc/`, which
  check parsers and emitters for every input within a bound, and the Lean
  4 proofs of `testing/proofs/lean4/`, which prove models of algorithms
  for every input. They take hours of CPU, so CI runs them after a push
  to main, in the `Proofs` workflow, never on a pull request, and leaves
  out the CBMC proofs `testing/proofs/cbmc/ci-skip.list` names, which
  need more time or memory than CI gives a proof. A change to code a
  proof covers, or to an algorithm a model follows, runs those proofs
  by name before it is sent, all of them after a change to `proof.h` or
  `run.sh`, and a new parser gets a proof where CBMC can carry one; the
  `proofs` skill says how.
- CI runs `.github/scripts/build-commits.sh`, `check-style.sh`,
  `check-dco.sh`, `check-coccinelle.sh`, `check-sparse.sh`,
  `check-spdx.sh`, `check-unused.sh`, `scan-build.sh` and the
  documentation check on every pull request;
  run them before handing work over, as the `pre-submit` skill says.
  Shell that a workflow runs lives in `.github/scripts/`, not inline in
  the workflow file.
- `make -C packaging bindeb-pkg`, `binrpm-pkg` and `bintar-pkg` build the
  distribution packages, each from `make clean`. The target package is
  fully static PIE and portable; the operator package links the host's
  shared libraries and is built on the distribution it is for
  (`PKG_ROLES=operator`), against a bpf-next `vmlinux.h`
  (`BPF_VMLINUX_H=`).

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
