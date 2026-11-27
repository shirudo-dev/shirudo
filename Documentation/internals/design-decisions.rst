..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: Kernel developers, security reviewers

Design decisions
================

This page collects the decisions that shape shirudo, the reason for each
and what it costs. Most of them follow from one goal: keep the code a
target has to trust, the kernel and shirudo, as small as possible, and
make every security decision where root cannot step around it.

A single binary for operator and target
---------------------------------------

The same ``shirudo`` executable runs on the operator host and on a
target, and its role follows from what is present: the signing key on
the operator, the sealed keyrings and the register on a target.

The reason is that both sides compute the same things. The operator's
``shirudo attest predict`` calls the functions the target uses to compute
the ``init`` event and fold the register, and both sides parse
``.upatch`` files with the same code. A second implementation would be
a second thing to get right and to keep in step.

The cost is a binary that contains operator commands a target never
runs. The code that holds the private key does not ship that way: the
CMS signer and the package builder and publisher are linked only into
the separate ``shirudo-build`` helper, and the core binary dispatches to
it.

Agentless targets
-----------------

A target runs no daemon and opens no listening socket. Every operation
is a one-shot ``shirudo`` command, started by hand, by a systemd timer, or
for ``upatch reconcile`` by systemd when udev reports a new network device.

A long-running process is something root can trace, stop or feed
input to for as long as it runs, and a socket is an attack surface for
anyone who can reach it. shirudo needs neither. Pins in the private bpffs
keep the enforcement and the upatches attached after ``init`` exits, the
kernel enforces without a helper, and the TPM keeps the record.

The cost is that nothing on the target watches continuously. Package
updates and telemetry run on timer periods, and a target reports its
state only when a command runs. A new network device is the one event a
command starts on, because a device left without its XDP upatch for a
whole period is exposed for that long; the command still does one pass
and exits.

Pull-based delivery
-------------------

The operator publishes signed packages to an OCI registry, and each
target pulls, verifies and loads them. shirudo has no push transport, no
SSH integration and no fleet inventory.

Nothing connects into a target, so a target has no inbound path to
defend. Registries already exist, scale, and need no shirudo code to
operate. The registry is not trusted: the signatures carry the trust, and
a ``.upatch`` that reaches a target any other way loads through the same
signature check. How an administrator reaches a target stays outside
shirudo.

The cost is latency: a fix reaches a target at its next update run, not
when the operator publishes it.

Stateless operator
------------------

The operator writes only its keypair (``shirudo genkey``) and the
artifacts and reports the caller names. It keeps no caches, no state
files, no logs of its own and no record of targets.

An operator host can then be rebuilt from the key alone, and there is no
operator state to tamper with or to leak. Every expectation a verifier
needs, such as ``--expect-chain``, either comes from the caller or is
computed from the artifacts by ``shirudo attest predict``.

Signed loaders instead of a userspace gate
------------------------------------------

The kernel verifies each upatch's signature on the ``BPF_PROG_LOAD`` that
loads it, and BPF LSM programs refuse every other way to install or
remove BPF. :doc:`signed-loader` explains why a service that checks
signatures before calling ``bpf()`` cannot work: root does not have to
ask it.

The cost is a dependence on a recent kernel ABI (see below), and a
detach that still runs in userspace because ``bpf_sys_bpf()`` offers no
detach.

ML-DSA-87 only
--------------

shirudo signs with ML-DSA-87 (FIPS 204, the largest parameter set) and
nothing else. ``shirudo genkey`` has no algorithm option, and the
signer, ``shirudo keys vouch`` and ``shirudo image verify`` refuse other
keys.

One algorithm means no negotiation and no downgrade. A key that anchors
a fleet's trust has to outlive hardware generations, so it gets the
largest margin of the post-quantum parameter sets, for about 2 KiB more
per signature than the smallest. The kernel verifies ML-DSA natively, so
the target needs no code of its own for it.

The costs: OpenSSL 3.5 or later on both sides, ``CONFIG_CRYPTO_MLDSA``
in the target kernel, and signatures of several kilobytes. TPM evidence
stays classical, because TPMs sign with ECDSA and RSA. The target checks
the algorithm of the certificates its pre-flight reads; it does not check
repository certificates or certificates a signed config adds, which
:doc:`/security/threat-model` lists.

A per-boot NV register
----------------------

The measurement lives in an NV extend index that clears at every TPM
reset, not in a PCR and not in a persistent index.

A stock system has no free static PCR, and PCR 23 is resettable. A
persistent index would carry history across boots and need an
authorization secret. A per-boot register starts from zero, so its value
is a function of the trust set, the restored upatches and the events
since boot, and the operator can predict it without any history. Its
write policy allows the first write only while PCRs 9 and 11 hold the
values ``init`` read when it bound it, and every write only with a
signature from a TPM-held key
whose extension command the kernel guards. The register follows the
construction of systemd's NvPCRs and adds the authorized writer.
:doc:`measurement-register` has the details.

A TPM 2.0 is mandatory. There is no unmeasured mode, because an
unmeasured target cannot be told from a tampered one.

Enforcement from the initrd
---------------------------

Enforcement comes up from the authenticated initrd, before the root file
system's services run, and ``init`` runs again from the root file system
to check and adopt what the first run did.

Anything that runs before enforcement can do what enforcement refuses,
and the evidence would not show it; the initrd shortens that window to
what the measured boot itself runs. A binding made in the initrd records
PCR 11 at its ``enter-initrd`` value, which systemd changes at
``leave-initrd``, so nothing later can make the first write that binding
allows. ``init`` can bind from the root file system after a TPM reset,
but with the values PCRs 9 and 11 hold then, which a verifier that pins
the initrd's values rejects. :doc:`boot-flow` follows both runs.

The costs: a dracut module, a measured UKI, an initrd that has to carry
the binary and its settings, and a second run of ``init``. A failed
``init`` does not stop the boot.

Shared enforcement guards shirudo's objects
-------------------------------------------

Some hosts need the upatches but also run BPF of root's own, a network
datapath such as Cilium. The runtime image can select
``enforcement.mode = shared`` for them, a setting of the image rather
than of the config image or the command line, so that the mode is part
of what PCR 11 pins and no later change loosens a strict target.

The mode does not filter root's commands against a list of what Cilium
needs, which would break with every release of every datapath. It
leaves ``bpf()`` to root and guards ownership instead: every route to a
map or program descriptor passes ``lsm/bpf_map`` or ``lsm/bpf_prog``,
which refuse the objects shirudo created, and links, which no hook sees
handed out, stay out of reach by id and by pin. What stays closed is
what would write shirudo's state past those hooks: LSM programs, whose
kfuncs write the seal's labels, and ``bpf_probe_write_user()``, which
lockdown refuses. Root's BPF still runs with kernel privilege, so the
mode is for hosts whose root is trusted with BPF, and evidence from
them does not cover what root loads (A16 and R25 in
:doc:`/security/threat-model`).

A single instance per host
--------------------------

One shirudo instance runs per host. The ``.bpf`` keyring, the private
bpffs, ``/var/lib/shirudo``, the ``security.bpf.shirudo`` attribute and
the NV index are single-tenant.

The kernel has one ``.bpf`` keyring and one set of LSM hooks, and the
guards would have to tell instances apart to allow one and refuse the
other. A single instance keeps each guard a single comparison.

CO-RE
-----

The enforcement objects and the upatches read kernel structures through
CO-RE relocations against the kernel's BTF, so one build runs on kernels
whose structure layouts differ.

A hard-coded offset signs as well as a relocated one, but on another
kernel it reads the wrong field; the signature cannot tell. CO-RE turns
a layout difference into a load failure.

State in BPF arenas
-------------------

A upatch that accumulates records keeps them in one
``BPF_MAP_TYPE_ARENA`` map and ships a ``shirudo_serialize__<map>``
program that walks them. Hash and array maps hold only what cannot live
in an arena: task, socket and per-CPU scratch state, keys the kernel
owns, and the serializer output.

An arena gives one consistent snapshot, memory the serializer can reset
between exports, and an overflow count the exported record carries. An
element-by-element read of a plain map gives a torn view, and a full
table drops records without saying so. :src:`upatches/kernel-obs/obs_table.h`
is the template. :doc:`/upatches/write/maps-arenas-serializers` explains it.

No target shell-outs
--------------------

Target commands use linked libraries and kernel interfaces and never
start another program. The dm-verity setup, for example, is made of
loop and device-mapper ioctls, not a call to ``veritysetup``, and the
target has no userspace hash-tree code: the kernel's dm-verity checks
every block.

A program the target started would be code outside the runtime image,
and an exec of a file outside the image clears the caller's runtime
authority. It would also bring its own environment, search path and
libraries into the trust decision. The operator's helper may run
``clang`` and ``veritysetup``; the operator holds no target authority.

No legacy kernel fallbacks
--------------------------

shirudo requires the signed-loader ABI, the BPF LSM hooks and current
clang and LLVM. A missing kernel feature fails the build, the pre-flight
or the load. There is no compatibility mode.

A fallback is a second, weaker path, and an attacker chooses which path
runs by choosing the conditions. The ABI check reads the kernel's BTF
rather than its release string, because a development tree can carry the
ABI before its version number says so. :doc:`kernel-interfaces` lists
what is required. The cost is a narrow set of kernels: bpf-next or a
release that contains its signed-loader work, with the patches in
:doc:`kernel-patches`.

A tree key the node never parses
--------------------------------

The node's parser of a tree publication, ``tree_parse()``, skips an
operation's ``fixes``. ``bpm tree append`` carries each earlier
operation's ``fixes`` into the next generation from a second read of
its own over the previous publication's bytes, with the JSON reader of
:src:`util/json.c`, in the operator's helper. The shared emitter,
``tree_emit_publication()``, takes an optional callback that adds keys
after an operation's ``artifact``, which the publisher passes and
nothing else does.

``tree_parse()`` is the node's parser of registry input. A key it reads
is a key a malformed document can make the node refuse, and ``fixes`` is
a convention of the keepalive backend that must never stop a node's
sync (:doc:`/reference/formats/bpm-formats`). The cost is that the
operator parses each previous publication twice. A single pass, in
which ``tree_parse()`` takes an optional field and sink for extra
operation keys that the publisher passes and the node leaves ``NULL``,
would read it once, at the price of a change to the node's parser and
to the ``bpm-tree-reader`` and ``bpm-tree-sync-model`` proofs that
include it.

A keepalive key for each run
----------------------------

``status --otel`` creates the attestation key it quotes the keepalive
with at every run, with ``TPM2_CreatePrimary`` under the endorsement
hierarchy, and flushes it after the quote. The key comes from a fixed
template, so every run gets the same key and the backend the same name;
nothing about it is kept on the target between runs.

The cost is a primary key derivation once a minute, which a slow
hardware TPM can take hundreds of milliseconds for
(:doc:`/operate/plan/overhead`). The optimization to take up if that
cost matters is to keep the key under a persistent handle,
``TPM2_EvictControl`` once and a lookup at every run. The rule against
a persistent index concerns the measurement register and does not
forbid it, but it adds TPM state that outlives a boot: a handle to
allocate, to find taken, and to clear on decommission.

Related
-------

- :doc:`architecture` for how the parts fit together
- :doc:`/security/threat-model` for what the design defends against
