<picture>
  <source media="(prefers-color-scheme: dark)" srcset="Documentation/logos/shirudo-horizontal-for-dark-back.png">
  <img src="Documentation/logos/shirudo-horizontal-for-light-back.png" width="350" alt="shirudo">
</picture>

\
[![CI suite](https://github.com/shirudo-dev/shirudo/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/tests.yml)
[![Build packages](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/packages.yml)
[![Documentation](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/docs.yml)
[![Sanitizers](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml/badge.svg?branch=main)](https://github.com/shirudo-dev/shirudo/actions/workflows/sanitizers.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

shirudo (Japanese シールド, pronounced “shee-roo-doh”) means “shield”

shirudo is an eBPF-based security platform. It ships eBPF "live patches",
called upatches ("micropatches"), to Linux targets without a reboot, and
it makes sure a target runs only the eBPF programs its operator signed.

upatches are written on top of shirudo and can harden or patch the
kernel itself or userspace applications; the goal is on-the-fly security
visibility, patching and attack-surface hardening in the age of LLMs, for
production systems whose patch and reboot cycles often span multiple days
if not weeks or months.

## Getting Started

Run `make docs` to render the documentation and access it through:
http://127.0.0.1:8000

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
