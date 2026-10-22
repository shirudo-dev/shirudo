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
changing security-relevant code, read `Documentation/architecture.rst`
and `Documentation/threat-model.rst`.

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
| `Documentation/threat-model.rst` | Authoritative security design: trust boundaries, threats, residual risks, deferred mitigations. Consult before touching any security-relevant path. |
| `Documentation/architecture.rst` | Implemented architecture, operator/target boundary, BPM package and upatch tree formats. |
| `Documentation/tpm.rst` | The measurement register, its events and eventlog, `shirudo attest` and its verification, the relation to systemd's NvPCRs and the known limits. Read it with the threat model before touching the TPM paths. |
| `Documentation/initrd.rst` | The production configuration: `init` run from the initrd and finished by the root file system, what survives switch-root, what the initrd needs, the dracut module, generator and installer under `tools/gen-initrd/`. |
| `Documentation/upatch.rst` | Authoring and shipping upatches: the BPF side, build and sign, test, the Beefile, `bpm build`, `push`, `tree append`, and the target's `bpm` commands. |
| `Documentation/features.rst` | Every attachment kind a upatch can have (fentry/fexit/fmod_ret, lsm, tp_btf, kprobe/kretprobe, uprobe.multi, cgroup_skb, netfilter), how the loader attaches each, what the target needs, and the serializer and test-run roles. |
| `Documentation/key-lifecycle.rst` | The signing keys and certificates: the trusted set a target enrols, vouching for a new key (`keys vouch`, `keys add`), rotation, revocation (`keys revoke`), custody. |
| `Documentation/operations.rst` | Day-two operation: units and timers, conditions, upgrades of shirudo and the kernel, decommissioning, backup, recovery, failure categories and exit status. |
| `Documentation/upatch-spec.rst` | The `.upatch` container and signing scheme. |
| `Documentation/requirements.rst` | Kernel options, operator toolchain, target runtime. |
| `Documentation/getting-started.rst` | Quickstart: build, sign, initialise a target, load and unload, publish and install packages. |
| `Documentation/telemetry.rst` | OTLP export of map snapshots and status keepalives, the signed Lua decoders, and collector integration (OpenTelemetry Collector, ClickHouse, Splunk, custom). |
| `Documentation/coding-style.rst` | The kernel's coding style, applied to all C here. |
| `Documentation/contributing.rst` | Commit message form, the mandatory `Signed-off-by:` and the kernel's attribution tags. Read it before crafting a commit. |

The kernel side of the signing design is the kernel's own
`Documentation/bpf/signing.rst`; `bpf_prog_verify_signature()` runs
before the LSM hooks and `attr.keyring_id` is a key serial, not a name.

## Coding conventions

- **Plain C.** Userspace and BPF both. No C++.
- **Zero-initialise with `= {}`, not `= {0}`.** The empty-initializer
  form is the kernel convention (a GNU extension shirudo's `-std=gnu11`
  accepts). Use it for every struct/array/union zero-init. When adding
  new code, write `= {}`.
- **Spell fixed-width integers the kernel's way**: `__u8`, `__u16`,
  `__u32`, `__u64` and `__s8` to `__s64`, from `<shirudo/misc.h>` in
  userspace and `vmlinux.h` in BPF, not `uint32_t` and its kin nor
  `unsigned int`, `unsigned long` and the like. `__u64` is `unsigned long
  long`, so it prints with `%llu`, and `ptr_to_u64()` turns a pointer
  into the `__u64` the bpf() ABI carries. A library interface that takes
  another type keeps it, and BPF programs spell hook arguments as the
  kernel's prototypes do. `check-style.sh` rejects `uint32_t` and its kin
  everywhere and `unsigned char`, `short`, `int` and `long` in userspace,
  less the files it names.
- **Parse numbers with `parse_u64()`, `parse_s64()` and `parse_x64()`**
  from `<shirudo/string.h>`, and find where one ends with `digits()`:
  they take a length, read nothing past it and refuse a sign, blank or
  base prefix. `check-style.sh` rejects `strtoul()` and its kin and
  `atoi()` outside `testing/`.
- **Copy strings with `strscpy()` and format into a fixed buffer with
  `strsprintf()`**, both from `<shirudo/string.h>`: `strscpy()` always
  terminates and returns `-E2BIG` when it cut, which a caller checks
  wherever a cut path or name would mean a different one, and
  `strsprintf()` returns `-E2BIG` with the buffer left empty rather than
  a cut path, in place of comparing `snprintf()` with the size by hand.
  `check-style.sh` rejects `strcpy()`, `strncpy()` and their kin and a
  `snprintf(dst, size, "%s", src)` copy outside `testing/`.
- **Declare locals in reverse-Christmas-tree order** (the netdev
  convention): longest declaration line first, shortest last. Group
  declarations that have no initializer dependency and sort them by
  descending line length; a declaration whose initializer references an
  earlier local must stay after it (correctness wins over the sort).
  Apply this whenever you add or touch a declaration block.
- **Linux kernel coding style** (`Documentation/coding-style.rst` —
  the kernel's own coding-style.rst, copied into this tree). Tabs
  (8-wide), 80-col soft limit and 100-col hard limit (checkpatch),
  K&R braces, no spaces inside parens.
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
  example in `Documentation/coding-style.rst` §8.
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

`Documentation/contributing.rst` is the kernel's process applied here
and is the reference for every commit an agent prepares: a subject of
the form `area: imperative summary`, a body that explains why before
what, and the `Co-developed-by`, `Fixes`, `Reported-by`, `Suggested-by`,
`Tested-by`, `Reviewed-by`, `Acked-by` and `Cc` tags used as the kernel
uses them. Every commit needs a `Signed-off-by:` from a real identity,
and only a person can give one: an agent never adds a sign-off, on its
own or anyone else's behalf, and leaves that line to the human who
reviews and submits the work. One logical change per commit, each one
building and passing on its own.

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
  Authorized Shirudo tasks may attach, pin and run the signed-loader data-map
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
- **Upatch state changes extend the TPM measurement register**
  with a domain-separated tag, in deterministic order. Commands refuse
  on drift (`tampered`) rather than retrying. Boot restore is exactly one
  register event and a re-run of `init` adds none. The register follows
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
  requires manual reboot after any interruption; Shirudo never reboots the
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
  an authorized caller may set the exact seal xattr. Both rename endpoints,
  write open, unlink, setattr and xattr changes are checked. There is no
  executable replacement exception.
  Label read errors require authority except ENODATA, EOPNOTSUPP, EACCES
  and EPERM; scratch allocation failure also requires authority. The seal
  labels new inodes during creation when the parent has a cached directory
  mark. Writers hold an open parent directory to retain that mark. Directory
  eviction and foreign link/rename entries remain limitations; existing
  writable descriptors and mappings are not revoked.
- **Single shirudo instance per host.** Keyring name, private bpffs,
  `/var/lib/shirudo`, the `security.bpf.shirudo` xattr namespace and
  the NV index are single-tenant by design.
- **Kernel + shirudo is the target TCB.** Ask of every change whether it
  grows the TCB; the agentless design exists to keep it minimal.
- **Bleeding-edge kernel and toolchain only.** The signed-loader ABI
  described in `Documentation/requirements.rst` and current clang/LLVM are
  hard prerequisites. Development trees can expose that ABI before the
  corresponding release number changes; use a verified commit, not just
  `uname`, to identify the tested kernel. No legacy-kernel fallback paths;
  a missing kernel feature fails the build or the load. x86-64, arm64 and
  riscv64 are the supported architectures.
- **BPF is CO-RE.** Hard-coded struct offsets sign fine and fail on the
  wrong kernel as `btf_mismatch`.
- **Upatch state lives in BPF arenas where possible.** A upatch that
  accumulates records keeps them in its one `BPF_MAP_TYPE_ARENA` map and
  ships a `shirudo_serialize__<map>` program that walks them; hash and
  array maps are for what cannot live in an arena: task, socket and
  per-CPU scratch state, lookup keys the kernel owns, and the serializer
  output. An arena gives one consistent snapshot, memory the serializer
  can reset between exports, and an overflow count the record carries,
  where an element-by-element read of a plain map gives a torn view and
  a table that silently fills up. `upatches/kernel-obs/obs_table.h` is
  the template to instantiate.

## Memory, JSON and logging

- Use the zeroing allocator in `util/malloc.{c,h}`: `xmalloc`/`xcalloc`
  return NULL on failure (never die), `xfree(ptr, size)` and
  `xstrfree` scrub before freeing. The libc allocators are poisoned
  project-wide; do not add exceptions, wrap in `util/malloc.c` instead.
  `xstrdup` is strlen-based, so never apply it to user, file or network
  input; use `xstrndup(s, bound)`. `xasprintf` formats into memory of
  the size needed, freed with `xstrfree`.
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
- `make -C testing test-op` runs the host-side suite (`testing/t0*`), no root needed;
  `make -C testing SANITIZE=address,undefined test-op` runs it under ASan and
  UBSan (CI does too); `make -C testing test-tgt` runs the target suite in the
  QEMU/swtpm VM (`make -C testing help` lists the VM target groups).
- `sudo make -C testing test-tgt` always boots the dm-verity runtime and signed
  config from a dracut initrd. CI runs that same required suite through
  `.github/scripts/target-tests.sh`; the old root-only installer suite is gone.
- `make -C testing fuzz [FUZZ_SECONDS=60]` runs the libFuzzer targets in
  `testing/fuzz/` for the parsers of input from outside the host, under
  ASan and UBSan, on their seed corpora; CI runs them too. A parser that
  takes such input gets a target there.
- `make -C Documentation html-docs` renders `Documentation/*.rst` with docutils in strict
  mode into `Documentation/output/`; CI runs it on every push, so run it
  after touching any document (python3-docutils provides `rst2html`).
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
  rejects the netdev block-comment opener. CI runs all three on every
  pull request, and `.github/scripts/build-commits.sh <range>` builds
  every commit of a pull request on its own; run them before handing
  work over.
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

Deferred work that is in scope is listed under deferred mitigations in
`Documentation/threat-model.rst`.
