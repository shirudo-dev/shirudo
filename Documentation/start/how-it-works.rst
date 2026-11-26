..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

How it works
============

This page follows one upatch from a kernel fix to a measured load on a
target, and back out again. Figure 1 shows the path: the operator host
builds and signs, an OCI registry stores, the target pulls and loads, its
kernel checks the signature, its TPM records the change, and the operator
verifies the record. The numbers in the figure match the steps below. The
background and internals pages linked from each step explain the
mechanisms in depth.

.. figure:: /images/start-how-it-works.svg
   :alt: The operator host builds, signs and pushes to an OCI registry. The
         target pulls, its kernel checks the signature and runs the loader,
         its TPM extends the register and signs evidence, which the
         operator verifies.

   Figure 1. The life of a upatch. Only the operator host holds the
   signing key, and only the target's TPM signs evidence.

Before the first upatch
-----------------------

A target enforces nothing until ``shirudo init`` has run. In production,
systemd runs it from the initrd of a measured unified kernel image (UKI),
before the root file system starts other workloads. ``init`` mounts the
runtime image whose dm-verity root hash the UKI carries, and the config
image whose signed root hash the kernel checks against its trusted keys,
among them the sealed ``.dm-verity`` keyring. It enrolls the trusted certificates in the kernel's
``.bpf`` keyring and seals it, loads the BPF LSM programs embedded in the
binary, restores the upatches archived on earlier boots and binds this
boot's measurement register in the TPM. The root file system runs ``init``
a second time to take over what the initrd set up.

From then on, the kernel accepts BPF programs from userspace only through
a signed loader. :doc:`/internals/boot-flow` describes the two runs, and
:doc:`/concepts/background/boot` and
:doc:`/concepts/background/initrd-dracut` explain the boot mechanisms they
rely on.

Build and sign
--------------

1. A upatch starts as BPF C source, often a few lines that refuse the
   call a kernel fix closes. It reads kernel structures through CO-RE, so
   the target kernel adjusts field offsets to its own layout when the
   program loads (:doc:`/concepts/background/co-re-btf`).

   A BPF object cannot be signed as it is. libbpf rewrites it while loading:
   it fills in map descriptors, applies relocations and resolves kernel
   symbols, so the bytes the kernel would check are not the bytes the
   operator built. shirudo therefore signs a loader instead. ``shirudo
   build`` hands the work to the operator-only helper ``shirudo-build``,
   which compiles the source with clang and lets libbpf generate a loader: a
   small program of type ``BPF_PROG_TYPE_SYSCALL`` that performs the load
   steps inside the kernel, with the payload programs in its data. The
   helper appends the upatch's name, its attach metadata and any decoders
   to that data, signs the loader instructions followed by the data with
   the operator's ML-DSA-87 key, and writes the ``.upatch`` file.

   The same command with ``--unload`` builds the unload directive that
   removes the upatch later. :doc:`/concepts/background/bpf-signing`
   explains the kernel's side of the scheme.

Package and publish
-------------------

2. ``shirudo bpm build`` reads a Beefile, builds each upatch it lists with
   its unload directive, and packs them into a ``.bee`` package.
   ``shirudo bpm push`` uploads the package to an OCI registry and, given
   the signing key, adds it to the registry's signed package index.
   ``shirudo bpm tree append`` can also publish the package's upatches as
   operations of a signed upatch tree, each with a selector that names the
   targets it applies to.

   The registry stores and serves bytes, and the design does not trust it.
   It can withhold or replay what the operator published, but it cannot
   produce an index, a tree or a upatch that passes the target's signature
   checks. :doc:`/concepts/upatches-and-packages` describes the objects, and
   :doc:`/concepts/background/oci` the registry protocol.

Pull
----

3. On the target, ``shirudo-bpm-repo-update.timer`` runs ``shirudo bpm repo
   update`` and then ``shirudo bpm upgrade``, a minute after the previous
   run ends. ``repo update`` fetches the index and checks its signature
   against the repository certificate in the signed config image.
   ``upgrade`` fetches the newest indexed version of each installed
   package, checks its digests against the index, unpacks it and loads its
   upatches. ``shirudo bpm install`` does the same for a package named by
   hand.

   ``shirudo-bpm-tree-sync.timer`` runs ``shirudo bpm tree sync`` every
   minute. It fetches the tree publication, checks its signature, and
   applies in sequence the operations whose selectors match this target.

Load
----

4. Every path ends in the same load, the one ``shirudo upatch load``
   performs. shirudo copies the loader's data into an array map, freezes
   the map, and makes it usable by this loader alone by naming the SHA-256
   of the loader's instructions. It then asks the kernel to load the loader
   with ``BPF_PROG_LOAD``, passing the signature and the ``.bpf`` keyring.

5. The kernel checks one signature over the loader's instructions followed
   by the frozen map contents, before its verifier runs. Two of shirudo's
   BPF LSM programs bracket that check. ``lsm/bpf`` admits a program load
   from userspace only for a signed ``BPF_PROG_TYPE_SYSCALL`` program, and
   ``lsm/bpf_prog_load`` admits it only when the kernel recorded the
   signature as verified against the ``.bpf`` keyring.

   shirudo then runs the loader. The loader creates the upatch's maps and
   loads its programs from kernel context, where the verifier still checks
   each one. shirudo attaches every program at the site the signed attach
   metadata names, compares the link the kernel reports with that site,
   and pins links and maps in its private bpffs under
   ``/run/shirudo/bpffs/upatches/``. It records the payload digest on the
   pin directory and archives the artifact in ``/var/lib/shirudo/upatches/``
   for the next boot. :doc:`/internals/signed-loader` walks through each
   system call, and :doc:`/concepts/background/bpf-lsm` explains the hooks.

Measure
-------

6. Once the artifact is archived, shirudo extends the measurement register
   with an event over the payload digest and the upatch's name, and appends
   a matching record to the eventlog. When the archive copy or the
   extension fails, shirudo undoes the load rather than leave it
   unmeasured. If the undo fails as well, the command says so and leaves
   the target for the operator to reconcile. A load stopped before the
   extension leaves pins the register does not cover; ``status`` reports
   them and the next load or unload undoes them.

   The register starts from zero at every boot. Its value depends only on
   the trusted certificates, the set restored at boot, the upatch tree's
   position and the events since then, so the operator can compute it
   without the target's history. :doc:`/concepts/measurement-register`
   explains why the register is built this way.

Attest
------

7. The operator chooses a fresh nonce, and ``shirudo attest
   --nonce=<hex>`` on the target produces evidence: a TPM quote over the
   PCRs and matching register certifications on either side of the quote,
   all signed by the TPM's attestation key, together with this boot's eventlog records. On the
   operator host, ``shirudo attest predict`` computes the register value
   the shipped certificates and artifacts must produce, and ``shirudo
   attest verify`` checks the signatures and the nonce, replays the records
   to the certified value and compares it with that expectation. Neither
   command opens a TPM. :doc:`/operate/run/attest` shows the procedure, and
   :doc:`/concepts/background/tpm` explains the TPM operations.

Export
------

Two more timers send telemetry while upatches run.
``shirudo-map-export.timer`` runs ``shirudo upatch map --all``, which reads
the maps of every loaded upatch, runs their serializers and signed Lua
decoders, and sends the records to the destinations the config image's
``map_export`` settings name. It runs five seconds after the previous run
ends. ``shirudo-keepalive.timer`` runs ``shirudo status --otel`` a minute
after the previous run ends, which sends the target's status record and
the TPM's quote of it as an OTLP log record when an endpoint is
configured.

Telemetry carries no proof of origin. The quote shows that a keepalive
arrived as the target's attestation key signed it, but the record is
still the target's own account, and the TPM-signed evidence of step 7
is the check. :doc:`/operate/run/telemetry` covers the export settings.

Unload
------

A upatch leaves the target through its unload directive. ``shirudo
upatch unload`` loads the directive's loader through the same signature
check, and that check is what authorizes the unload. The loader itself
never runs. shirudo compares the payload digest the directive names with
the one recorded on the upatch's pin, and refuses with
``payload_mismatch`` when they differ.

shirudo extends the register with the unload event before it removes the
pins. An unload interrupted between the two leaves a register that records
more than happened, never a detach the register does not know. shirudo
also deletes the archived copy, so the next boot does not restore the
upatch. ``shirudo bpm uninstall`` and a tree ``delete`` operation remove
upatches through their directives in the same way.

Related
-------

- :doc:`what-is-shirudo` for the problem shirudo addresses and its scope
- :doc:`/concepts/operator-and-target` for what each side holds
- :doc:`/internals/architecture` for the components and their code
- :doc:`/security/security-model` for what each step protects against
  and where it stops
