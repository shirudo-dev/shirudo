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
It ships eBPF "live patches", called upatches, to Linux targets without a
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

* [Getting started](Documentation/getting-started.rst): build, sign,
  initialise a target, load and unload, publish and install packages
* [Architecture](Documentation/architecture.rst): why shirudo exists,
  its design properties and how all fits together
* [Features](Documentation/features.rst): every attachment kind a
  upatch can have and how each one works
* [Requirements](Documentation/requirements.rst): kernel requirements,
  operator toolchain, target runtime
* [Operations](Documentation/operations.rst): watching a target,
  upgrades, decommissioning, backup, recovery and more
* [Threat model](Documentation/threat-model.rst): trust boundaries,
  the threats addressed and the residual risks
* [Telemetry](Documentation/telemetry.rst): the OTLP export and how
  to integrate with collectors
* [Contributing](Documentation/contributing.rst)

The full index is in [Documentation/index.rst](Documentation/index.rst).

## License

shirudo is licensed under the [BSD-2-Clause License](LICENSE). BPF
programs are dual-licensed `Dual BSD/GPL`. Each source file holds a
SPDX license identifier.
