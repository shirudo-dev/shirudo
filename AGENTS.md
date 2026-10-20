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
- **Declare locals in reverse-Christmas-tree order** (the netdev
  convention): longest declaration line first, shortest last. Group
  declarations that have no initializer dependency and sort them by
  descending line length; a declaration whose initializer references an
  earlier local must stay after it (correctness wins over the sort).
  Apply this whenever you add or touch a declaration block.
- **Linux kernel coding style** (`Documentation/coding-style.rst` —
  the kernel's own coding-style.rst, copied into this tree). Tabs
  (8-wide), 80-col soft limit, K&R braces, no spaces inside parens.
  Apply to userspace too — eases review. **Comments are scarce and
  follow §8**: WHAT/WHY at the function head, not HOW inside the
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
- **Comments are scarce.** Kernel style: explain the *why*, not the *what*.
  No multi-paragraph docstrings. No "added for issue X" or "used by Y" — those
  go in commit messages.

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

- **No subprocesses, no daemons.** The core `shirudo` binary never
  forks or execs on either side; every external operation goes through
  a linked library. The single exception is the operator-only dispatch
  in `builtin-build.c`: `shirudo build` and the operator bpm commands
  exec the separate `shirudo-build` binary, which signs in-process and
  execs `clang`. `shirudo-build` and `clang` ship only in the operator
  package, so the invariant is absolute on every target-side path. A
  feature that seems to need a shell-out needs a library binding, not
  `system(3)`.
- **Operator code does not ship to targets.** Signing (`util/sign.c`)
  and the package builder and publisher (`tools/shirudo-build/`) are
  linked only into `shirudo-build`. The core binary only dispatches.
- **The signature-gated `BPF_PROG_LOAD` is the trust boundary.** Every
  signed artifact (the LSM bootstrap, every load and unload directive)
  goes through the same load path; a second loading path is wrong.
  Userspace may attach, pin and run the signed-loader data-map
  pattern, because none of those can introduce unsigned code; detach,
  update and corruption of BPF objects from userspace are denied by the
  LSM. In the `lsm/bpf` hook the `bool kernel` argument is the
  discriminator: calls from inside a signed loader are allowed,
  userspace calls are filtered.
- **The operator never touches the kernel keyring or the TPM; the
  target never touches the private key.**
- **The bpf keyring is the trust anchor; the user keyring is staging.**
  `init` enrols the trusted set in the kernel's `.bpf` keyring and
  seals it, which needs the kernel booted with `bpf.keyring_unsealed=1`
  and `init` run from the initrd; a kernel that sealed it empty at boot
  makes `init` stage the primary certificate alone in a sealed
  `shirudo` user keyring until the next reboot. The set (`util/keys.c`)
  is `cert.der` plus every `trusted/<fingerprint>.der` with a vouch
  beside it that verifies under a member, less what `revoked/` names;
  a file without a vouch is not a member, so the set extends itself
  only on the word of a key already in it (`keys vouch` on the
  operator, `keys add` on the target). The kind and serial of the
  keyring `init` sealed, and the serials of its keys, live in the
  identity map it freezes and pins in the bpffs; a load names the
  keyring that record says, `lsm/bpf_prog_load` admits only that kind,
  and for a staged user keyring only that serial (the kernel records
  none for its own bpf keyring), and `lsm/key_permission` lets shirudo
  alone write, unlink, revoke or invalidate the keyring and its keys.
  `keys revoke` is the only way a key leaves during a boot: marker in
  `revoked/` first, then the unlink, the measured `key_revoke` event
  and the purge of everything the key signed. There is no file pin to
  forge or lose.
- **The operator is stateless.** It writes only the keypair (`genkey`)
  and the artifacts or reports the caller names. No hidden caches,
  state files, logs or staging directories; `--expect-chain` comes
  from the caller or from `shirudo attest predict`.
- **Every target state change extends the TPM measurement register**
  with a domain-separated tag, in deterministic order, and refuses on
  drift (`tampered`) rather than retrying. Boot restore is exactly one
  register event and a re-run of `init` adds none. The register follows
  systemd's NvPCR construction (`util/chain.c`): an NV extend index that
  clears at TPM reset, a first write only possible while PCRs 9 and 11
  hold the values the policy was computed from, which is why `init`
  runs from the initrd before `leave-initrd` moves PCR 11, and the
  index name extended into PCR 9 right after it. Do not reintroduce a
  persistent index or
  an auth value derived from the certificate; the upatch tree measures
  into the same register. A TPM 2.0 is mandatory; there is no
  unmeasured mode.
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
- **init runs twice in production and the two halves are fixed.** The
  initrd run (`shirudo-initrd.service`, detected by `/etc/initrd-release`
  with the root at `/sysroot`) enrols the initrd's own
  `/etc/shirudo/keys/cert.der`, attaches the LSM with its pins under
  `/run/shirudo/bpffs`, records the root's binary as the lasting
  identity beside its own, restores the archived upatches read through
  a read-only bind of `/sysroot/var/lib/shirudo`, binds the register
  and leaves the init record at `/run/shirudo/eventlog.pending`. The
  root run labels the tree and adopts that record. Anything else the
  initrd would write to the root is wrong: the root is read-only there,
  and `/run` is the only thing systemd carries across switch-root
  besides the API file systems. Non-systemd initrds are unsupported.
- **Single shirudo instance per host.** Keyring name, private bpffs,
  `/var/lib/shirudo`, the `security.bpf.shirudo` xattr namespace and
  the NV index are single-tenant by design.
- **Kernel + shirudo is the target TCB.** Ask of every change whether it
  grows the TCB; the agentless design exists to keep it minimal.
- **Bleeding-edge kernel and toolchain only.** Linux v7.4 or newer
  and current clang/LLVM are hard prerequisites. No legacy-kernel detection, no
  runtime feature-probe fallbacks; a missing kernel feature fails the
  build or the load. x86-64, arm64 and riscv64 are the supported
  architectures.
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
  input; use `xstrndup(s, bound)`.
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
  `make target` the static-OpenSSL target profile (`make target-deps`
  builds OpenSSL, libcurl and tpm2-tss from source first).
- `make -C testing test-op` runs the host-side suite (`testing/t0*`), no root needed;
  `make -C testing SANITIZE=address,undefined test-op` runs it under ASan and
  UBSan (CI does too); `make -C testing test-tgt` runs the target suite in the
  QEMU/swtpm VM (`make -C testing help` lists the VM target groups).
- `make -C testing test-tgt TEST_VM_INITRD=1` boots the guest from a dracut initrd
  that runs `shirudo-initrd.service`; CI runs `test-tgt` both ways through
  `.github/scripts/target-tests.sh`. `make -C testing test-installer` runs
  `testing/t1300-installer-e2e.sh`, the installer end to end in a QEMU
  guest with a vTPM, two reboots included.
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
  distribution packages. The target package is static apart from glibc
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
