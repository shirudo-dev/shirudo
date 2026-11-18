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
append`` adds its tree entries to an upatch tree, for targets that follow
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
   with your key, and tags the package with its version. The index
   namespace is the package repository path without its final name. It
   prints the pushed reference and the manifest's digest,
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

Segments and registry retention
-------------------------------

A tree grows past what one signed document holds as a chain of
segments. Once the current segment holds 64 operations, or the number
``--segment-ops`` gives, ``tree append`` seals it and publishes the new
operations as the next segment, which names the sealed one by digest.
One append always goes into one segment, and a segment never holds more
than 512 operations. ``<tree>:stable`` names only the current segment; a
target that is behind fetches the sealed ones by digest.

Every sealed segment is tagged ``segment-1``, ``segment-2`` and so on in
the tree's repository. Keep the ``segment-*`` tags: a registry that
deletes untagged manifests, or a retention policy that prunes old tags,
would remove a segment a target still has to walk through, and the
target then refuses to sync rather than skip it.

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
