<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Documentation/logos/shirudo-horizontal-for-dark-back.png">
  <img src="Documentation/logos/shirudo-horizontal-for-light-back.png" width="350" alt="shirudo">
</picture>

\
[![Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml)
[![CI suite](https://github.com/shirudo-dev/shirudo/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/tests.yml)
[![Sanitizers](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml)
[![Proofs](https://github.com/shirudo-dev/shirudo/actions/workflows/proofs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/proofs.yml)
[![CodeQL](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml)
[![Documentation](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml)<br/>
[![Coverage Status](https://coveralls.io/repos/github/shirudo-dev/shirudo/badge.svg?branch=main)](https://coveralls.io/github/shirudo-dev/shirudo?branch=main)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/33401/badge.svg)](https://scan.coverity.com/projects/shirudo-dev-shirudo)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/999999/badge)](https://www.bestpractices.dev/projects/999999)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shirudo-dev/shirudo/badge)](https://scorecard.dev/viewer/?uri=github.com/shirudo-dev/shirudo)

shirudo (Japanese シールド, pronounced “shee-roo-doh”) means “shield”.

shirudo is a BPF-based security platform: Linux targets run only the BPF
their operator signed, every change is measured into the TPM, and
functionality ships as signed
[upatches](https://docs.shirudo.dev/upatches/learn/concepts.html)
(“micropatches”) that targets pull from OCI registries.

## Use cases

Users, developers and agents write upatches on top of shirudo, and
shirudo makes sure that only signed upatches run and that every change
is on record.

- **Live patching for kernel and userspace.** Security mitigations that
  block vulnerable code paths. They complement traditional kernel live
  patching with a faster rollout and bridge kernel and userspace
  deployment cycles.
- **System hardening.** Sandboxes for containers, Kubernetes Pods and
  LLM agents, and kernel hardening implemented as upatches.
- **Runtime security and observability.** For kernel and userspace
  applications, LLM agents included. Data is collected and aggregated
  in BPF maps and pushed over OpenTelemetry into collectors.
- **Embedded and edge devices.** Devices that are hard to patch get
  upatches the same way servers do. shirudo runs on x86-64, arm64 and
  riscv64 and adds little to the trusted computing base beyond the
  kernel.

## Properties

- Always on: the platform is part of the trusted computing base and
  starts from initrd in early boot
- Signed and sealed: BPF is admitted only through loaders signed
  against the sealed BPF keyring, and the platform guards its own
  assets against a root user who does not hold the signing key
- In-kernel control plane: every load and unload is a signed loader the
  kernel verifies before it runs
- Measured: a TPM-backed register records every operation on upatches,
  and the TPM signs it for a remote verifier
- Lightweight core: shirudo protects its own assets and nothing else.
  Everything else ships as upatches
- Plain BPF C: upatches are small BPF C programs that engineers and
  agents can read, generate and maintain. Commands take and produce
  structured data
- Pull in, push out: targets pull upatches from OCI registries and push
  telemetry to collectors; nothing on a target listens for connections

The [threat model](https://docs.shirudo.dev/security/threat-model.html)
states where each of these mechanisms stops.

## How it works

[![The operator host builds, signs and pushes to an OCI registry. The target pulls, its kernel checks the signature and runs the loader, its TPM extends the register and signs evidence, which the operator verifies.](Documentation/images/start-how-it-works.svg)](https://docs.shirudo.dev/start/how-it-works.html)

The life of a upatch. Only the operator host holds the signing key, and
only the target's TPM signs evidence.
[How it works](https://docs.shirudo.dev/start/how-it-works.html) follows
one upatch through each numbered step.

## By role

- New to shirudo:
  [Quickstart](https://docs.shirudo.dev/start/quickstart.html), then
  [FAQ](https://docs.shirudo.dev/start/faq.html)
- Operators, who deploy and run targets:
  [Deployment checklist](https://docs.shirudo.dev/operate/deploy/deployment-checklist.html),
  then [Read shirudo status](https://docs.shirudo.dev/operate/run/read-status.html)
- upatch authors:
  [Your first upatch](https://docs.shirudo.dev/start/guides/first-upatch.html),
  then [From a kernel fix to a upatch](https://docs.shirudo.dev/upatches/learn/kernel-fix-tutorial.html)
- Security reviewers:
  [Security model](https://docs.shirudo.dev/security/security-model.html),
  then [Threat model](https://docs.shirudo.dev/security/threat-model.html)
- Contributors:
  [Develop locally](https://docs.shirudo.dev/contribute/code/develop-locally.html)

## Specifications

- [Beefile](https://docs.shirudo.dev/reference/formats/beefile.html):
  the Beefile that describes a package
- [.upatch format](https://docs.shirudo.dev/reference/formats/upatch-format.html):
  the signed `.upatch` container
- [upatch tree](https://docs.shirudo.dev/reference/formats/upatch-tree.html):
  the operations, segments and publication document of a upatch tree
- [Keepalive](https://docs.shirudo.dev/reference/formats/keepalive.html):
  the record a target sends its collector, its
  [body](https://docs.shirudo.dev/reference/formats/keepalive.html#keepalive-body-format)
  and its TPM quote

## Documentation

The documentation is at **[docs.shirudo.dev](https://docs.shirudo.dev/)**.

## Releases

**There is no shirudo release yet.**

[main](https://github.com/shirudo-dev/shirudo/commits/main/) is the
development branch and no stable branches are maintained at this point.
Until the first release, every push to main builds the packages in the
[Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml)
workflow, where they are available as run artifacts. Once releases
start, each release tag publishes its packages on
[GitHub Releases](https://github.com/shirudo-dev/shirudo/releases)
and the actively maintained releases are listed here.

For upgrades of shirudo and the kernel on a target, consult
[Upgrade shirudo and the kernel](https://docs.shirudo.dev/operate/maintain/upgrade.html).

### Architectures

shirudo supports x86-64, arm64 and riscv64. Operator and target may be
on different architectures; the upatch format is little-endian and
the signature is architecture-neutral.

### Software Bill of Materials

Every package comes with a Software Bill of Materials (SBOM) in
[SPDX](https://spdx.dev/) format.

## License

shirudo is licensed under the [BSD-2-Clause License](LICENSE). BPF
programs are dual-licensed BSD/GPL. Each source file holds a SPDX
license identifier. The tree vendors a few source files from
third-party projects under different but compatible licenses; those
files retain their original SPDX identifier and copyright notices.
