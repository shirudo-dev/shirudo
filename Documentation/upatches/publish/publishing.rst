..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: upatch authors

Publish a package
=================

Publishing makes a package reachable for targets in two ways. ``bpm
push`` puts it into an OCI repository and adds it to the registry's
signed index, for targets that install packages by name. ``bpm tree
append`` adds its tree entries to a upatch tree, for targets that follow
the tree without naming anything. The registry only transports: targets
verify the operator's signatures on the index, the tree and every upatch.

Before you begin
----------------

- An operator host with the operator package installed, or a checkout
  with ``shirudo-build`` on the path, as :doc:`/reference/cli/build`
  describes.
- The signing key whose certificate your targets trust, in a key
  directory. The same key signs the upatches, the index and the tree.
- A package directory with a Beefile, as :doc:`/reference/formats/beefile`
  describes, whose
  upatches you have tested, as :doc:`/upatches/test/testing` describes.
- Push access to an OCI registry. shirudo reads credentials from
  ``BPM_OCI_USERNAME`` and ``BPM_OCI_PASSWORD``, ``BPM_OCI_BEARER_TOKEN``,
  ``REGISTRY_AUTH_FILE`` or the Docker configuration, and an extra CA
  from ``BPM_OCI_CA_FILE``. :doc:`/reference/environment` lists them.

Build the package
-----------------

1. Build and sign the package:

   .. code-block:: console

      operator$ shirudo bpm build <package-dir> --version <version> \
          --keys-dir <keys-dir>

   ``<package-dir>`` holds the ``Beefile``; pass ``--file <file>`` for a
   Beefile with another name. ``<version>`` is the new version and
   ``<keys-dir>`` your key directory. The command prints the path of
   ``<name>-<version>.bee``, which it writes into the current directory.

   Targets order versions by their numeric ``major.minor.patch`` and
   upgrade to the highest, and the signed index refuses a version it
   already lists with other content. Give every build that leaves the
   operator host a new version.

2. Read the package back:

   .. code-block:: console

      operator$ shirudo bpm info <name>-<version>.bee
      operator$ shirudo bpm info upatches <name>-<version>.bee --all

   The first command prints the ``README.md`` the package carries, the
   second its load and unload artifacts. ``shirudo bpm key fingerprint
   <name>-<version>.bee`` prints the fingerprint of the signing
   certificate the package carries.

Push it to a repository
-----------------------

3. Push the package and add it to the signed index:

   .. code-block:: console

      operator$ shirudo bpm push <name>-<version>.bee \
          oci://<registry>/<namespace>/<name> --keys-dir <keys-dir>

   ``<registry>`` is the registry's host and ``<namespace>/<name>`` the
   repository, without a tag. The command uploads the package as an OCI
   artifact, attaches the package's certificate to it as a referrer, adds
   the version with the package's digests to the index at
   ``<namespace>/bpm-index:stable`` in the same registry, signs the index
   with your key, and tags the package with its version: the objects
   on the left of Figure 1. The index namespace is the package
   repository path without its final name. It prints the pushed
   reference and the manifest's digest,
   ``oci://<registry>/<namespace>/<name>:<version> sha256:<digest>``;
   ``bpm config update`` takes that digest to build on the package.

   The first package of a namespace needs ``--new-index``: ``bpm push``
   refuses a namespace without an index otherwise, so that a registry that
   hides the index cannot have you sign one without the packages it
   listed. ``--new-index`` is refused where an index exists.

   Without ``--keys-dir``, or ``--index-cert`` and ``--index-key``, the
   command pushes the package and moves the version tag, but leaves the
   index unchanged and does not check that the version is new. Targets
   that install by name do not see such a push.

4. Verify that the registry serves the package:

   .. code-block:: console

      operator$ shirudo bpm info oci://<registry>/<namespace>/<name>:<version>

   The command downloads the package and prints its ``README.md``.

Append it to the tree
---------------------

5. Publish the package's ``[upatches.tree]`` entries as ``add``
   operations:

   .. code-block:: console

      operator$ shirudo bpm tree append <name>-<version>.bee \
          oci://<registry>/<namespace>/<tree> --tree-id <tree-id> \
          --keys-dir <keys-dir>

   ``<tree>`` is the tree's repository. The command fetches the current
   publication at ``<tree>:stable`` and verifies its signature against
   your certificate. For every entry it checks that the artifact is a
   load directive whose upatch name equals the entry's ``id``, pushes the
   artifact as an artifact of its own, and appends an operation with the
   entry's selector and, when the entry has one, its ``fixes`` list. It
   then signs the next generation, which names the previous
   publication's digest as its parent, and prints the tree's reference
   and new digest. Every earlier operation goes into the new generation
   as it was, its ``fixes`` included.

   A repository without a publication starts a new tree at generation 1,
   with the id ``--tree-id`` gives, else the package name at ``stable``
   and ``<package>-<reference>`` at another reference, so that a canary
   tree has an id of its own. To extend an existing tree, ``--tree-id``
   must name the id it has, from your own records: a registry that serves
   another tree your key signs at that reference is refused. ``--reference
   <ref>`` publishes to another tag than ``stable``, such as a canary
   tree.

6. To withdraw an entry, publish its unload directive as a ``delete``:

   .. code-block:: console

      operator$ shirudo bpm tree append <name>-<version>.bee \
          oci://<registry>/<namespace>/<tree> --tree-id <tree-id> \
          --keys-dir <keys-dir> --op delete

   Nothing is ever removed from the tree: a ``delete`` is a new operation
   after the ``add``, and carries no ``fixes``. To replace a loaded
   upatch with a new build of the same name, append the ``delete`` of the
   old package first and the ``add`` of the new one after it, since a
   target cannot load a second upatch under a name that is already
   loaded.

``tree append`` refuses an ``add`` whose XDP programs select a device
class that another upatch of the tree selects on the same nodes, since a
device runs one native XDP program and the second load would stop every
such node's ``tree sync``. Give each class to one upatch, give the two
entries selectors that exclude each other, such as different values of
one label, or append the ``delete`` of the earlier upatch first.
:doc:`/reference/cli/bpm` has the exact rule.

Publish every shield at once
----------------------------

A shield is a package whose Beefile has an ``[upatches.tree]`` entry,
one that a tree can take. :src:`tools/put-shields` runs steps 1 and 3
for every shield of the checkout, so that one namespace lists them all
before you choose which to append:

.. code-block:: console

   operator$ tools/put-shields --version 1.0.0 --keys-dir <keys-dir> \
       --new-index oci://<registry>/<namespace> >append.sh
   put-shields: pushed oci://<registry>/<namespace>/cve-2025-71093-e1000-tbi-detector:1.0.0 sha256:b751…
   put-shields: pushed oci://<registry>/<namespace>/cve-2026-31675-netem-detector:1.0.0 sha256:f369…
   put-shields: pushed oci://<registry>/<namespace>/cve-2026-63984-rpl-detector:1.0.0 sha256:23c4…

It builds every ``Beefile`` and ``*.bee`` under :src:`upatches/` that has
an ``[upatches.tree]`` entry, or, when you name Beefiles and directories
after the namespace, those Beefiles and the ones under those
directories, each once, and pushes each package to
``oci://<registry>/<namespace>/<package>``. Each entry of
``<namespace>/bpm-index:stable`` then names a shield's repository,
version and digests. Give ``--new-index`` for a namespace that has no
index, and a new ``--version`` for every run after the first: ``bpm
push`` refuses a version the index lists with other content, and a new
build has other content. ``SHIRUDO`` names the ``shirudo`` binary, and
the ``BPM_OCI_*`` variables reach the registry as they do for ``bpm
push``.

Keep the version short. A member path of a package,
``<package>-<version>/upatches/<upatch>.unload.upatch``, holds at most 99
bytes, which leaves the kernel-cve detectors 8 characters of version:
past that, ``bpm build`` fails with ``File name too long``.

It reports each push on standard error and writes to standard output,
for each shield, the ``tree append`` command that takes it from the
registry by its reference and manifest digest, with the tree left to
fill in:

.. code-block:: console

   operator$ cat append.sh
   shirudo bpm tree append oci://<registry>/<namespace>/cve-2025-71093-e1000-tbi-detector:1.0.0 --package-digest sha256:b751… oci://<registry>/<tree> --tree-id <tree-id>
   shirudo bpm tree append oci://<registry>/<namespace>/cve-2026-31675-netem-detector:1.0.0 --package-digest sha256:f369… oci://<registry>/<tree> --tree-id <tree-id>
   shirudo bpm tree append oci://<registry>/<namespace>/cve-2026-63984-rpl-detector:1.0.0 --package-digest sha256:23c4… oci://<registry>/<tree> --tree-id <tree-id>

Run the lines of the shields you choose with your tree's repository and
id, and ``--keys-dir``. The digest decides which package is appended:
the registry can point the tag at another package your key signed, and
``tree append`` refuses one whose manifest has another digest.

``--catalog <file>`` also writes the shields it pushed, with their fixes
and selectors, for the keepalive backend to list as available
(:doc:`/operate/backend/shields-put`). When a build or a push fails, the
file holds the shields pushed before it: load it, and push the rest
under the same version, naming their Beefiles.

Segments and registry retention
-------------------------------

A tree grows as a chain of segments. Once the current segment holds 64
operations, or the number ``--segment-ops`` gives, ``tree append`` seals
it, tags it ``segment-<k>`` and publishes the new operations as the next
segment, which ``<tree>:stable`` names. Figure 1 shows the namespace this
leaves, and :doc:`/reference/cli/bpm` the exact rule.

.. figure:: /images/reference-tree-registry.svg
   :alt: One registry namespace holds a package repository with its
         package manifest and certificate referrer, the bpm-index
         repository whose signed index document pins the package
         manifest and archive by digest, and the tree repository. In the
         tree, the segments tagged segment-1 with seq 1 to 64 and
         segment-2 with seq 65 to 128 and the current one tagged stable
         with seq 129 to 150 each hold a signed document and its
         signature, and each names the one before it by
         base.segment_manifest_digest. The operations pin artifact
         manifests tagged upatch-id-payload16. Superseded generations
         are untagged and may be collected. A node at seq 70 walks back
         from stable to segment-2 by digest and then applies seq 71 to
         128 and 129 to 150, oldest first.

   Figure 1. A namespace after ``bpm push`` and ``bpm tree append``, with
   a target at seq 70 that is behind.

Keep the tags: ``:<version>``, ``bpm-index:stable``, ``stable``,
``segment-*`` and ``upatch-*``. A target fetches packages, sealed
segments and artifacts by digest, so a retention policy that prunes old
tags, or a registry that then deletes untagged manifests, removes an
object a target may still have to fetch: ``bpm tree sync`` then refuses
rather than skip it, and an install or upgrade fails. A superseded
generation of a segment or of the index, which the next append or push
took the tag from, may be collected.

An ``add`` whose XDP programs select a device class makes ``tree
append`` fetch every sealed segment, so its class check covers the whole
tree. Expect three fetches per sealed segment for such an ``add``, its
manifest, document and signature; any other operation fetches none.

What a target does with them
----------------------------

A target learns its repositories, their index certificates and the tree
it follows from its signed config image.
:doc:`/operate/run/deliver-packages` shows the setup.

For a package by name, ``shirudo bpm repo update`` fetches the index and
verifies its signature. ``shirudo bpm install <source>/<name>`` checks the
package's manifest and archive against the digests in the index, refuses
a package whose ``cert.der`` has another public key than the target's
``/var/lib/shirudo/keys/cert.der``, and loads every
``upatches/*.upatch`` of the package, each one measured. The
``shirudo-bpm-repo-update.timer`` runs ``bpm repo update`` and then
``bpm upgrade`` at boot and a minute after each run, so a pushed version
reaches the targets that have the package installed within minutes.

For the tree, ``shirudo-bpm-tree-sync.timer`` runs ``bpm tree sync``
every minute. It fetches the publication, verifies the signature, the tree
id and the chain of parent digests, and goes through the operations it has
not seen in order. For each one whose selector matches, it fetches the
artifact once, checks its payload digest, name and kind against the
operation, loads or unloads it, and measures the operation. An operation
whose selector does not match is passed over for good.

The kernel verifies the signature of every upatch at load in either case,
whatever the registry served.

Next steps
----------

- :doc:`/reference/formats/bpm-formats` for the index
- :doc:`/reference/formats/upatch-tree` for the tree
  documents
- :doc:`/operate/run/deliver-packages` to configure targets
- :doc:`/operate/run/attest` to verify what targets loaded
