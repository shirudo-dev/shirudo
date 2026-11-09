..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

upatches, directives and packages
=================================

An operator ships BPF code to targets as a small set of objects. The
upatch is the unit the target loads, and its unload directive is the unit
that removes it. A package bundles related upatches into one versioned
file, a repository's signed index lists the packages it serves, and the
upatch tree says which target applies which upatch, in which order. This
page explains what each object is, who signs it, what the target checks
before it acts on it, and how the objects relate. Table 1 at the end
summarizes them.

upatches
--------

An upatch is one BPF object, built and signed as a unit: one or more
programs, their maps, and the metadata that says where each program
attaches. The target loads, pins, archives and measures it as a whole.

Every upatch has a name, by default the base name of its source file. A
name consists of letters, digits, ``.``, ``_`` and ``-``, does not start
with a dot, and has at most 255 characters, each dot counting as two,
because the pin directory spells it ``~d``. It names the pin directory
under ``/run/shirudo/bpffs/upatches/``, the archived copy
``/var/lib/shirudo/upatches/<name>.upatch`` that ``init`` restores at boot,
and the events in the measurement register.

Load artifacts
~~~~~~~~~~~~~~

A load artifact is the ``.upatch`` file that installs an upatch. It holds
a fixed header, the instructions of a signed loader, the loader's data,
and a CMS signature over the instructions followed by the data. The data
carries what the loader installs: the payload programs and the map
definitions. :doc:`/concepts/background/bpf-signing` explains why the
signature covers a loader and not the BPF object itself.

The data also carries the sections the target reads for itself: ``NAME``
with the upatch's name, ``UPGM`` with the attach metadata and, when the
programs declare decoders, ``DCDB`` with their Lua sources. Because these
sections sit inside the signed data, the kernel's signature check covers
them as well. A section outside the signed data could be changed on the
way without the signature noticing.

The header repeats the name and holds the payload digest: SHA-256 over the
loader instructions followed by the data. The target recomputes the digest
and compares the header's name with the signed one, and refuses an
artifact on any difference. The payload digest is the upatch's identity
from then on. shirudo records it on the pin directory as the
``security.bpf.shirudo.payload`` extended attribute, measures it with the
name into the register, and an unload directive must name it.
:doc:`/reference/formats/upatch-format` gives the byte layout.

Signed attach metadata
~~~~~~~~~~~~~~~~~~~~~~

The signature covers the payload programs' instructions, but instructions
do not always say where a program runs. For ``fentry``, ``fexit``,
``fmod_ret``, ``lsm`` and ``tp_btf`` programs the attach target is part of
the loaded program. For a kprobe, a uprobe, a ``cgroup_skb`` or a
``netfilter`` program, the site is chosen when shirudo creates the link:
the kernel symbol and offset, the binary and its file offsets, the cgroup
or the network namespace. A site taken from an unsigned file, or from the
caller, would let root run the operator's signed code where the operator
never meant it to run.

The attach metadata therefore travels as a signed section. Each program
entry carries a role, an attach kind and, for kprobes, the symbol and
offset. Uprobe entries add the target binary's path, its GNU build ID and
the probe offsets. After attaching, shirudo compares the link the kernel
reports with the metadata and refuses with ``attach_scope_mismatch`` when
they differ. :doc:`/upatches/write/attach-kinds` lists the kinds and the check
for each.

The role says what shirudo does with a program. An attach program is
attached and pinned. A serializer, named ``shirudo_serialize__<map>``, is
pinned and run by ``shirudo upatch map`` to read one of the upatch's maps.
A test-run program is run once at load, after the attachments, and a
negative return fails the load. :doc:`/upatches/write/maps-arenas-serializers`
covers serializers.

Unload directives
~~~~~~~~~~~~~~~~~

An unload directive is the signed instruction to remove one upatch. It
uses the same container with the unload flag set. Its loader comes from
shirudo's fixed unload template, and its signed sections are ``NAME``, the
upatch to remove, and ``UNLD``, the payload digest that upatch must have.
The operator builds it with ``shirudo build --unload``, giving the name
and the payload digest of the upatch to remove.

A plain ``unload <name>`` command would not do, because root can run
shirudo's commands on a target. Removing a mitigation must take the same
key as installing one. ``shirudo upatch unload`` therefore loads the
directive's loader so that the kernel checks its signature, and never runs
it. shirudo then compares the signed digest with the attribute on the pin
directory. Equal digests let the unload go ahead, different ones refuse
with ``payload_mismatch``, and a missing pin is reported as
``already_unloaded``. The digest ties a directive to one build of the
upatch, so a directive made for an old version does not remove a newer
one with the same name.

The detach itself happens in shirudo's userspace after the check, because
a loader running in the kernel cannot detach a link or remove a pin. The
:doc:`/security/threat-model` records what that leaves open.

Packages
--------

A package groups upatches that belong together into one versioned file.
Its definition is a Beefile, a file in a subset of TOML in the package
directory. The Beefile names the package and lists its upatch sources,
optional generators for read-only data, extra files to ship and, per
upatch, the selector it gets when published to an upatch tree.
:doc:`/upatches/publish/beefile` describes every key.

``shirudo bpm build`` builds and signs every upatch the Beefile lists,
together with its unload directive, and writes ``<name>-<version>.bee``.
The package is a gzip-compressed tar archive that holds the Beefile, the
artifacts and directives under :src:`upatches/`, the package's ``README.md``
when it has one, the signing certificate ``cert.der``, a
``build-environment.json`` and the extra files.

A package carries no signature of its own. A repository's signed index
lists its digest, and every upatch inside carries its own signature, which
the kernel checks at load. A package installed from a direct ``oci://``
reference bypasses the index, and then only the upatch signatures protect
it.

Repositories and signed indexes
-------------------------------

A repository is an OCI registry that a target knows by name, together
with the certificate that signs its index. On a target, repository
definitions and their certificates come from the config image, and local
changes to them are refused. :doc:`/concepts/background/oci` explains the
registry protocol.

``shirudo bpm push`` uploads a package as an OCI artifact. Given the
signing key, it also adds the package to the registry's index at
``<namespace>/bpm-index:stable``: a JSON document that lists each package's
name, version, manifest digest and package digest, with a detached CMS
signature in a second layer. ``push`` refuses to list a version again
with different content, so a version published through the index does not
change. A push without the signing key uploads the package without
touching the index.

On the target, ``shirudo bpm repo update`` fetches the index, verifies the
signature against the repository's certificate and keeps the verified
copy in sealed state. ``shirudo bpm install`` and ``shirudo bpm upgrade``
choose versions from that copy, and check the manifest and package digests
they download against it before unpacking. ``upgrade`` removes the
installed version's upatches through their directives, loads the new
version's upatches, and restores the old set when a load fails.
:doc:`/operate/run/deliver-packages` shows the commands.

upatch tree
-----------

An index says which versions exist. It does not say which target should
run what, or in which order. The upatch tree does.

The tree is an append-only, ordered list of operations. Each operation
adds or deletes one upatch and carries a selector over the target's
architecture, kernel release prefix, kernel build ID, kernel configuration
values and node labels. ``shirudo bpm tree append`` pushes each upatch as
an OCI manifest of its own and publishes the next generation of the list,
the tree publication, as a JSON document with a detached CMS signature.
Each generation names the one it replaces.

A target subscribes to a tree through its config image. ``shirudo bpm
tree sync`` verifies the publication against the active config's non-revoked BPF
signer set, evaluates each new operation's selector on the target, and
applies the matching operations in sequence order. Each applied operation
loads or unloads the upatch and is then measured as a tree operation
event. An operation whose selector does not match is passed over for good:
the target's position moves beyond it, and a later kernel or label change
does not bring it back.

The target keeps a projection root, a hash chain over the operations it
applied, and the next boot's init event includes it. The register value
an operator predicts therefore covers the tree as well as the archived
upatches. :doc:`/upatches/publish/publishing` shows how to publish to a tree,
and :doc:`/reference/formats/bpm-formats` gives the document formats.

How the objects relate
----------------------

Each object carries its own protection, and the target checks it before
acting on it. Table 1 lists what the operator signs, where the target
checks it, and what the measurement register records.

.. list-table:: Table 1. Shipped objects and their checks
   :header-rows: 1
   :widths: 18 24 34 24

   * - Object
     - Signed by the operator as
     - Checked on the target by
     - Recorded in the register as
   * - Load artifact
     - CMS signature over the loader instructions and data
     - The kernel at ``BPF_PROG_LOAD``, against the ``.bpf`` keyring
     - An ``upatch_load`` event
   * - Unload directive
     - The same
     - The kernel at ``BPF_PROG_LOAD``, then the payload digest against
       the pin's attribute
     - An ``upatch_unload`` event
   * - Package
     - Not signed as a whole
     - Its digests against the signed index, then each upatch as above
     - The events of its upatches
   * - Signed index
     - Detached CMS signature
     - ``bpm repo update``, against the repository certificate from the
       config image
     - Not recorded
   * - Tree publication
     - Detached CMS signature
     - ``bpm tree sync``, against the runtime image's certificate
     - A ``tree_op`` event per applied operation, after the upatch's own
       event

Limits
------

A signature proves who built an upatch and that nobody changed it. It
says nothing about whether the upatch is correct. The kernel's verifier
checks memory safety, and the rest is the author's responsibility.

A signature does not expire. A target accepts any artifact that verifies
against its trusted set, including an older build that a registry serves
again, and nothing enforces a minimum version.

A directive is bound to a name and a payload digest, not to the key that
signed the load. Any key in the trusted set can sign a directive that
removes any upatch.

Related
-------

- :doc:`/start/how-it-works` for the path of one upatch
- :doc:`/upatches/learn/concepts` for authoring upatches
- :doc:`/concepts/measurement-register` for the events
- :doc:`/internals/signed-loader` for the load in detail
