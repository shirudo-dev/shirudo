..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

Operator and target
===================

Every shirudo deployment has two roles. The operator decides which BPF
code a target may run, and the target enforces that decision. One binary serves both, and
what is on a machine decides its role: a machine with the private signing
key acts as an operator, and a machine whose kernel enrolled shirudo's
certificates and attached its enforcement acts as a target. ``shirudo
status`` prints the roles it detects. A development host can hold both.

Why the roles are separate
--------------------------

The main adversary on a target is root without the signing key: a
compromised administrator account, a container escape, an implant. Root can
read any file, so any key stored on a target is root's key. If the target
held the signing key, root could sign its own BPF, and the kernel's
signature check would admit it. We therefore keep the key on a separate
operator host and give targets only public certificates.

The obvious way to connect the two is a management service that pushes
signed code to every target. That service needs a listener on each target,
credentials to reach it, and an inventory of the fleet, and each of those is
something to attack and something to trust. The design has no such
service. The operator publishes to an OCI registry, and each target pulls
and verifies on its own.

Operator
--------

The operator host holds the private signing key, ``signing_key.pem``, and
its certificate, ``cert.der``. ``shirudo genkey`` creates both, with an
ML-DSA-87 key, in the keys directory: ``--keys-dir``, else
``SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``. The operator signs
upatches and unload directives, package indexes and tree publications,
config image roots and vouches for further keys, all with ML-DSA-87.

The operator also verifies. ``shirudo attest verify``, ``shirudo attest
predict`` and ``shirudo attest challenge`` work offline on the operator
host, from files. The operator never opens a TPM and never touches a
kernel keyring. :doc:`/operate/maintain/keys` covers the custody of the key.

shirudo-build helper
~~~~~~~~~~~~~~~~~~~~

The code that signs artifacts is not in the core ``shirudo`` binary.
Every operator command except ``genkey`` and the offline ``attest``
commands executes a separate helper, ``shirudo-build``: ``build``, ``bpm
build``, ``bpm push``, ``bpm tree append``, ``bpm config update``, ``image
build``, ``image verify`` and ``keys vouch``. The helper links the
signer, runs clang to compile BPF and runs ``veritysetup`` to build and
check images. The core binary finds it through ``SHIRUDO_BUILD``, then
the installed path under ``libexec``, then ``PATH``.

The operator package installs the helper and the target package does not.
On a target the operator commands fail with exit status 127, and neither a
signer nor a compiler driver is code that root could reach there.

Stateless operator
~~~~~~~~~~~~~~~~~~

The operator writes only the key pair and the files the caller names:
artifacts, packages, images, challenges and reports. It keeps no cache, no
inventory of targets and no record of what it published.

Everything a check needs comes from the caller. To verify a target, the
operator names the certificates, the artifacts that should be installed
and, when events happened after boot, the expected register value, which
``shirudo attest predict`` computes from the same inputs. The registry
holds what was published, and each target's TPM holds what was installed.
An operator host can therefore be rebuilt from the key and the artifacts,
and every expectation a verification applies is on its command line rather
than in a local file.

Target
------

A target is a Linux machine with a TPM 2.0 that runs the core binary from
an authenticated image, enforces signatures in its kernel and keeps a
measurement of its BPF state. It never holds the private signing key.
Table 1 lists what it does hold.

.. list-table:: Table 1. State on a target
   :header-rows: 1
   :widths: 40 30 30

   * - What
     - Where
     - Protected by
   * - The ``shirudo`` executable, the initial BPF certificate, the config
       verification certificate and the bootstrap settings
     - Runtime image, mounted at ``/run/shirudo/runtime``
     - dm-verity, with the root hash taken from the initrd in the UKI
   * - Repositories and their certificates, the tree subscription, node
       labels, vouched and revoked certificates, export settings
     - Config image, mounted at ``/run/shirudo/config``
     - dm-verity, with a signed root hash
   * - The trusted certificates
     - The kernel's ``.bpf`` keyring
     - Sealed by ``init``, and ``lsm/key_permission``
   * - Enforcement links, the identity map, the tamper counters, upatch
       links and maps
     - The private bpffs at ``/run/shirudo/bpffs``
     - BPF LSM hooks on unlink, rename, mount and descriptor access
   * - Archived upatches, the eventlog, package and tree state, cached
       images, the config activation journal
     - ``/var/lib/shirudo``
     - Seal labels
   * - The measurement register
     - An NV index in the TPM
     - The index's write policy and ``lsm/tpm_command``

Runtime and config images
~~~~~~~~~~~~~~~~~~~~~~~~~

Two dm-verity images carry what root must not be able to change. The
kernel checks every block it reads from them against a root hash, so a
changed byte fails the read (:doc:`/concepts/background/dm-verity`).

The runtime image holds the executable and what it must trust before
anything else: the initial BPF certificate, the certificate that verifies
config images, and the bootstrap settings that name the config image and
its measurement PCR. The UKI's initrd carries the runtime image's root
hash, so the measured boot covers it.

The config image holds what an operator changes during operation. Its
root hash is signed, and the kernel checks the signature against the
``.dm-verity`` keyring, into which ``init`` enrolls the runtime image's
config certificate before sealing it. ``shirudo image update`` activates a
new config image without a reboot and measures it into a separate PCR.
The kernel also accepts a config signed by a key in its built-in trusted
keyring and, depending on its configuration, in the secondary or platform
keyring; the :doc:`/security/threat-model` lists this among the threats to
resolve.

Neither image replaces the host's root file system. Both are read-only,
and the config image is mounted ``noexec``. :doc:`/internals/config-images`
describes their layout, activation and measurement.

Runtime authority and task marks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Root can run any program, so the enforcement programs cannot recognize
shirudo by its path, its name or its user. We tie authority to provenance
instead. A task gains the task mark only through a successful exec of a
file on the authenticated runtime image: ``bprm_check_security`` stages
the decision and ``bprm_committed_creds`` commits it once the exec has
succeeded. A forked child inherits its parent's mark, a successful exec of
any other file clears it, and a failed exec leaves it unchanged. The exec
of a runtime file is refused when the task is being traced or runs under
seccomp, so neither a debugger nor a filter installed beforehand controls
the new process.

Runtime authority is what the mark grants. The BPF LSM programs require
it for the ``bpf()`` commands that create, update or freeze maps, run
programs, attach links and pin objects, and for every map or link
descriptor, whether taken by pin, by ID or by opening a pin in the private
bpffs. They require it to change pins, to write, rename or relabel sealed
state under ``/var/lib/shirudo``, to change the keys in the ``.bpf`` and
``.dm-verity`` keyrings, and to extend shirudo's register in the TPM.
Other tasks cannot trace a marked task or open a perf event on it.

A program load from userspace needs a verified signature in addition,
whatever the caller's mark. Runtime authority lets shirudo create, attach
and pin what a signed loader produced. It never lets any process load code
the operator did not sign.

The mark authorizes a process, not a person. Root can still run the
runtime binary, and that process acts with authority within what its
commands do: ``shirudo upatch map`` run by root reads upatch maps, and
without ``--peek`` it drains a serializer-backed map. Every executable on
the runtime image gets the same authority, so the image must hold only
what is meant to have it, and no shells, interpreters or debuggers.
:doc:`/internals/seal` explains the marks and labels in detail.

Agentless target
~~~~~~~~~~~~~~~~

A target runs no daemon and listens on no socket. Every operation is a
one-shot command, started by root or by a systemd unit, that does its work
and exits: ``init`` at boot from the initrd and again from the root file
system, package and tree updates every minute, and map export and status
keepalives every five seconds.
:doc:`/reference/systemd-units` lists the units and timers.

What must outlive a command is pinned in the private bpffs, and what must
outlive the boot is archived under ``/var/lib/shirudo`` and restored by
``init``. We accept the cost of this design, which is latency: a target
learns of a new package at its next timer run, and besides a new network
device starting ``upatch reconcile``, nothing on it reacts between runs.
In return there is no long-running process for root to
attack, no socket for the network to reach, and less code in the target's
trusted computing base.

Limits
------

The separation protects the key only while the operator host is
trustworthy. An adversary who holds the signing key can sign BPF that
every target accepts, and the design treats that adversary as the
operator.

A registry cannot forge what the operator signed, but it can withhold new
publications or serve older signed ones. A target accepts any upatch whose
signature verifies against its trusted set, including an old one.

Signers are added only at boot. A live config activation can revoke a
key, but a new signer enters the ``.bpf`` keyring only when ``init``
enrolls the trusted set. :doc:`/operate/maintain/keys` describes what can change
when.

Related
-------

- :doc:`/start/how-it-works` for the path of one upatch between the roles
- :doc:`/internals/architecture` for the components and their code
- :doc:`/security/security-model` for the trust boundaries
- :doc:`/reference/cli/index` for the commands of each role
