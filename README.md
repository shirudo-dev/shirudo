<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Documentation/logos/shirudo-horizontal-for-dark-back.png">
  <img src="Documentation/logos/shirudo-horizontal-for-light-back.png" width="350" alt="shirudo">
</picture>

\
[![Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml)
[![Documentation](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml)
[![Sanitizers](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml)
[![CodeQL](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

shirudo ("shields", JP) is an eBPF security platform for the agentic era.
It ships eBPF "live patches", called upatches ("micropatches"), to Linux targets without a
reboot, and it makes sure a target runs only the eBPF programs its operator signed.
upatches can harden or patch the kernel itself or userspace applications;
the goal is on-the-fly security visibility, patching and attack-surface
hardening in the age of LLMs, for production systems whose patch and
reboot cycles often span multiple days if not weeks.

For example, the Linux kernel's CVE stream runs at dozens of fixes a day,
exploitation now regularly precedes the patch, and a fleet reboot cycle
might takes weeks in the worst case. shirudo exists for the window in
between: an agent, engineer or hybrid workflow derives an eBPF mitigation
from the fix, the operator signs it, and the fleet pulls it within a short
time window, measured and revocable. There is deliberately no configuration
DSL, since agents work better with plain code. Note, shirudo is not limited
to just mitigations, it serves as a platform and can deploy any eBPF programs
into the fleet.

## Getting Started

Run `make docs` to render the documentation and access it through:
http://127.0.0.1:8000

## Releases

**There is no shirudo release yet.**

[main](https://github.com/shirudo-dev/shirudo/commits/main/) is the
development branch and no stable branches are maintained at this point.
Until the first release, every push to main builds the packages in the
[Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/deb.yml)
workflow, where they are available as run artifacts. Once releases
start, each release tag publishes its packages on
[GitHub Releases](https://github.com/shirudo-dev/shirudo/releases)
and the actively maintained releases are listed here.

For upgrades of shirudo and the kernel on a target, consult
[Upgrade shirudo and the kernel](Documentation/operate/maintain/upgrade.rst).

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
