..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

FAQ
===

Short answers to the questions newcomers ask most, each with the page
that explains it.

Can I test shirudo somewhere first?
-----------------------------------

Yes. The `online getting-started lab
<https://labs.isovalent.com/#/lab/shirudo-getting-started>`__ runs
shirudo in a browser. On your own Linux machine,
:doc:`/start/quickstart` boots a test target in a virtual machine.

What is a upatch?
------------------

A signed program that shirudo loads into a running system without a
reboot, to act in the kernel or in user space. See
:doc:`/upatches/learn/concepts`.

Is every upatch a BPF program?
------------------------------

No. Most are BPF programs, in the kernel or on functions of user space
programs through uprobes. A Java agent upatch patches the JVMs that load
it (:doc:`/upatches/write/java-agents`). Kernel live patches are planned
as upatches too, tracked in `issue 83
<https://github.com/shirudo-dev/shirudo/issues/83>`__. Support for
other user space runtimes is planned as well.

Which kernel does a target need?
--------------------------------

A bpf-next kernel for now, because shirudo's BPF uses its signed-loader
ABI. The repository carries :doc:`a few kernel patches
</internals/kernel-patches>` on top, which the project plans to
upstream. :doc:`/operate/plan/system-requirements` lists the kernel
options. Before the first release, the project plans to add a mode for
older kernels too, for environments where root is trusted.

Does a target need a TPM?
-------------------------

Yes. Every target currently needs a TPM 2.0, which records every change
to the loaded upatches and signs the evidence for a remote verifier.
Before the first release, the project plans to add a mode for older
kernels, for environments where root is trusted, which uses no TPM. See
:doc:`/concepts/background/tpm`.

Does a target run in a cloud VM or a microVM?
---------------------------------------------

Yes, where the VM has a TPM 2.0, such as the virtual TPM of a cloud
provider or a VMM, and boots a signed UKI under UEFI Secure Boot, so
that the boot is measured. shirudo then runs in the VM's own kernel as
it does on a physical machine. The test VM is a QEMU guest of this kind,
with a software TPM. :doc:`/operate/plan/system-requirements` lists
what a target needs, and :doc:`/operate/deploy/boot-integration` how it
boots.

Who decides which upatches run on my machines?
----------------------------------------------

Only holders of a signing key your targets trust. You create each key
with ``shirudo genkey`` on your operator host, and targets hold only its
certificate. See :doc:`/operate/maintain/keys`.

Who holds the signing key, and how is it protected?
---------------------------------------------------

You do. ``shirudo genkey`` writes each ML-DSA-87 signing key on your
operator host, mode ``0600``. The key stays there, and a target holds
only its certificate. Guard that host. A key signs any upatch for every
target that trusts it, and anything it ever signed can load again. Vouch
for a standby signer in the first config, so that you can revoke the
primary key later and keep signing. Revoking a key also purges the
upatches it signed. :doc:`/operate/maintain/keys` covers key management.

Do I need to rebuild my kernel to enroll a signing key?
-------------------------------------------------------

No. Your keys are not built into the kernel, so changing them never
takes a new kernel build. The kernel starts the ``.bpf`` and
``.dm-verity`` keyrings open when it boots with
``bpf.keyring_unsealed=1`` and ``dm_verity.keyring_unsealed=1``. In the
initrd, ``init`` enrolls your certificates from the signed runtime and
config images and then seals both keyrings. This is the kernel's own
mechanism, which systemd's ``systemd-keyring-setup`` also uses from
version 263. On a shirudo target ``init`` does the enrollment, so no
other unit may seal the keyrings before it
(:doc:`/operate/deploy/boot-integration`). See
:doc:`/operate/maintain/keys`.

Is there an official shirudo OCI registry for upatches?
-------------------------------------------------------

No. For now the project provides shirudo and its tooling, and you run
your own registry. :doc:`/upatches/publish/publishing` says how to
publish to one. Third-party projects offer registries with upatches, but
the `shirudo-dev <https://github.com/shirudo-dev>`__ community has not
reviewed or vouched for those upatches. Use them at your own risk.

Can I build an end-to-end shirudo pipeline at home?
---------------------------------------------------

Yes. One machine can be the operator host and run the OCI registry and
an OpenTelemetry Collector; your targets follow the upatch tree in that
registry and send their telemetry back to the collector.
:doc:`/start/guides/backend` sets this up on one host with the test VM
as the target, and :doc:`/operate/deploy/deployment-checklist` takes a
real target through deployment.

Does shirudo depend on an outside service or account?
-----------------------------------------------------

No. You create the keys, sign the packages and choose the registries.
Code someone else signed loads only if your signed config vouches for
its signer. See :doc:`/concepts/operator-and-target`.

Does shirudo send data anywhere?
--------------------------------

Only to the endpoints you set up and configure. The operator host pushes
what you publish to the registry you name, and a target pulls from that
registry and sends telemetry to the collector you name, as in the
end-to-end pipeline above. That collector can run in your own local
network. With none configured, shirudo sends nothing.
:doc:`/operate/plan/overhead` lists each request a target makes.

Is there a daemon or an open port?
----------------------------------

No. Every operation is a one-shot command, run by hand or by a systemd
timer, and nothing on a target listens for connections, so shirudo adds
no open port to a target's attack surface. Targets pull packages from
OCI registries and push telemetry to a collector. See
:doc:`/concepts/operator-and-target`.

Do I need an AI model to write a upatch?
----------------------------------------

No. A upatch can be BPF C, a Java jar or another kind in the future,
and ``shirudo build`` signs it. Write it by hand, or with a coding agent
that a person guides and checks, so that the two work together. The
agent can use any model, open-weight ones included, and can follow
:src:`.agents/skills/upatch/SKILL.md`. Nothing loads until a key holder
signs it.

Does a signed upatch mean it works?
-----------------------------------

No. The signature proves who built it, the BPF verifier proves memory
safety, attestation proves what loaded; whether it mitigates is the
author's job. Test a upatch before it ships, as the next answer
describes. :doc:`/upatches/write/index` covers writing one, and
:doc:`/upatches/learn/examples` describes the upatches the tree ships.

How do I test a upatch safely?
------------------------------

Try it on the test VM first. The VM plays a production target. It runs
``init`` from a dracut initrd with the signed runtime and config images,
on a software TPM. Load the upatch there, watch what it does and unload
it again (:doc:`/upatches/test/testing`).

On a fleet, ship a version that only observes before the one that
refuses. It counts the calls the refusing version would block and
blocks nothing, so you see what it would hit before anything is
refused. The detectors in :doc:`/upatches/learn/examples` work that way.

How do I roll out a upatch to part of a fleet?
----------------------------------------------

Give your targets labels in their signed config, such as ``env=canary``
and ``env=prod``, and publish the upatch for the canary label first.
When it behaves there, publish it again for the next label. A target
checks each publication once. If its labels do not match, it skips that
publication and does not come back to it, even when its labels change
later. Targets pick up a publication within about a minute, and
``shirudo bpm tree sync --dry-run`` on a target shows what it would
apply. See :doc:`/operate/run/deliver-packages`.

How do I take a upatch back?
----------------------------

Publish a ``delete`` for it to the upatch tree, and every target that
follows the tree unloads it within about a minute. On one target,
``shirudo upatch unload`` with the upatch's signed unload directive
removes it at once. The register records both. See
:doc:`/start/guides/live-patching`.

How does shirudo compare with other security tools?
---------------------------------------------------

The docs compare shirudo with kernel live patching, IMA and IPE, BPF
policy engines, signed BPF, measured boot, security agents, web
application firewalls and network filtering in
:doc:`/concepts/comparisons`.

Why not use kernel live patching instead?
-----------------------------------------

The two complement each other. A live patch replaces a kernel function
with native code that no verifier checks, built for one kernel build. A
upatch blocks a vulnerable path with verified, measured BPF that loads
on more than one kernel build, until a live patch or a fixed kernel is
in place. See :doc:`/concepts/comparisons`.

Can a target run kernel live patches?
-------------------------------------

Yes, if every live patch module is signed with a key the kernel trusts.
shirudo refuses unsigned modules, so root cannot load an unsigned one to
get around the upatches. See :doc:`/operate/plan/interoperability`.

Do shirudo and kernel live patches replace regular kernel and application upgrades?
---------------------------------------------------------------------------------------

No. A upatch or a kernel live patch covers the time between two
upgrades, until the machine runs a kernel or an application with the
fix, and is removed then. Neither replaces the upgrade itself. Automate
the upgrades of kernels and applications and work to shorten their
cadence, so that the time a mitigation has to cover stays short.
Mitigation is also only one use of upatches. They observe, harden and
contain workloads as well, as :doc:`/start/who-is-shirudo-for`
describes, and :doc:`/start/what-is-shirudo` says what shirudo does and
does not do.

How does shirudo differ from a BPF policy engine such as Tetragon?
------------------------------------------------------------------

Tetragon describes what to trace and enforce in a policy language of its
own, TracingPolicy, written in YAML. Its agent loads its own BPF
programs and configures them from those policies, which it takes at
runtime from policy files or its command-line client on any Linux host,
and on Kubernetes also from custom resources. It assumes root is
trusted. Its threat model says a fully privileged user can stop the
agent, change its policy and unload or replace its programs.

shirudo has no policy language. It ships upatches, signed BPF loader
programs built on the operator host, and a target admits only BPF from
loaders the kernel verifies against a sealed keyring. It takes no
policy at runtime and runs no agent. Every change is a signed upatch
that the TPM register records, so root without the signing key can
neither load other BPF nor detach the enforcement. See
:doc:`/concepts/comparisons`.

Does shirudo replace a web application firewall?
------------------------------------------------

No, it adds a layer. A WAF filters the requests of known exploits on
the network path, and firewalls and network policies on switches, or on
the DPU in a node, filter traffic before it reaches the host. A upatch
runs on the host and blocks the kernel or application call an exploit
needs, so it works even when the exploit arrives encrypted or encoded in
a way the WAF does not recognize. Networking upatches can also filter a
host's traffic, for example with L2 to L4 filters or DDoS mitigation, or
redirect it to a WAF. Each of these is one layer of defense, and shirudo
complements the others with one on the host. See
:doc:`/concepts/comparisons`.

Can root turn shirudo off?
--------------------------

Not without the signing key: root cannot load unsigned BPF or detach the
enforcement. Root with a way into the kernel itself, such as a kernel
exploit or a module signed with a key the kernel trusts, goes around
every check made in that kernel. :doc:`/security/security-model` lists
what shirudo protects and where it stops, and
:doc:`/operate/plan/hardening` lists the kernel settings it relies on.

What can root still do on a target?
-----------------------------------

Run any command of the runtime binary. Root can apply any published
unload directive and load any artifact ever signed, an older vulnerable
version included. The register records each, so a verifier that expects
a state sees the change. See R1, R2 and R16 in
:doc:`/security/threat-model`.

Is shirudo ready for production?
--------------------------------

Not yet. shirudo is pre-release and has no stable releases or supported
release branches, and the architectures are not all at the same stage.
See :doc:`/reference/versions` and :doc:`/contribute/arch-support`.

Are forks and registries that use the name part of the project?
---------------------------------------------------------------

No. The project's repositories are under `github.com/shirudo-dev
<https://github.com/shirudo-dev>`__, and its documentation is at
`docs.shirudo.dev <https://docs.shirudo.dev/>`__. A fork that drops the
TPM, the kernel patches or the signed loaders enforces less than these
pages describe.

Where can I ask questions or discuss shirudo?
---------------------------------------------

On `shirudo's Zulip <https://shirudo.zulipchat.com>`__, which is for community support. Ask questions about using shirudo in
the `#help channel
<https://shirudo.zulipchat.com/#narrow/channel/659552-help>`__, and
bring ideas and design to the `#ideas-design channel
<https://shirudo.zulipchat.com/#narrow/channel/659583-ideas-design>`__.
File bugs, regressions and feature requests as GitHub issues, also when
they come up on Zulip, and report a security problem privately, as
:doc:`/security/reporting` describes.
:doc:`/contribute/support` lists every channel.

Can Cilium, Falco or bpftrace run on a target?
----------------------------------------------

Not as they are. shirudo admits only BPF loaded by signed loaders, so
tools that load their own programs fail at their first map or program.
Their logic can ship as signed upatches instead. Before the first
release, the project plans to address this.
:doc:`/operate/plan/interoperability` goes through common tools.

What happens when the registry is unreachable?
----------------------------------------------

Nothing changes on the target. Loaded upatches keep running, the update
fails and the next run of the timer tries again. See
:doc:`/operate/plan/scalability`.

What happens when init fails at boot?
-------------------------------------

The boot continues, and what the target enforces depends on where
``init`` stopped. :doc:`/operate/deploy/initialize` lists each case and
what to do.

Can I sign with an existing key?
--------------------------------

No. shirudo signs with ML-DSA-87 only, a post-quantum algorithm, and
the signing code refuses any other key. Create the key with
``shirudo genkey``, as :doc:`/operate/maintain/keys` describes.

Do I need to know BPF to write a upatch?
-----------------------------------------

A upatch is plain BPF C or a Java jar. :doc:`/start/guides/first-upatch`
writes one from scratch, and :doc:`/upatches/learn/kernel-fix-tutorial`
takes a real kernel fix to a published package.

Which architectures does shirudo run on?
----------------------------------------

x86-64, arm64 and riscv64, at different stages: CI tests x86-64, the
test VM also runs on arm64, and no riscv64 target has booted yet.
:doc:`/contribute/arch-support` compares the three.

Can I try shirudo on macOS?
---------------------------

shirudo runs only on Linux. On an Apple M3 or later with macOS 15 or
later, :doc:`set up a Lima VM </start/quickstart-macos>` to run the
quickstart. The test VM runs inside the Lima VM.

How much does shirudo cost on a target, and how far does it scale?
------------------------------------------------------------------

:doc:`/operate/plan/overhead` gives the files, memory, CPU time and
network traffic of one target, and :doc:`/operate/plan/scalability` how
the registry load grows with a fleet and where a target and a upatch
reach their limits.

Is there a talk that introduces shirudo?
----------------------------------------

Yes, it was first presented at the Linux Plumbers Conference 2026 in
Prague in the talk `shirudo: BPF live-patching infra for the agentic
era <https://lpc.events/event/20/contributions/2437/>`__. Its page
links the slides and the video.
