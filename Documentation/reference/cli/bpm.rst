..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators, upatch authors

shirudo bpm
===========

Install, upgrade and remove signed packages of upatches on a target, and
build and publish them to an OCI registry from the operator host.

Runs on: per subcommand, see the table. Target subcommands run as root
with the runtime binary. Requires: per subcommand. Changes measured state:
``install``, ``upgrade``, ``uninstall`` and ``tree sync`` yes, the others
no.

Usage
-----

.. code-block:: none

   shirudo bpm config register add <source> oci://<registry> [--index-repository <repository>] (--cert <certificate> | --cert=<certificate>)
   shirudo bpm config register list
   shirudo bpm config register (remove | rm) <source>
   shirudo bpm config update --base-package <package> --version <version>
                             [--file <beefile>]
                             [--rodata-input <name>=<path>]... [--keys-dir <dir>]
   shirudo bpm repo update [<source>]
   shirudo bpm tree sync [--dry-run] [--report <path> | --report=<path>]
   shirudo bpm tree append <package> oci://<registry>/<repository> [<append-options>]
   shirudo bpm key (add | fingerprint) <certificate | package | oci-reference>
   shirudo bpm key list [--json]
   shirudo bpm pull oci://<registry>/<repository>:<tag>
   shirudo bpm info <package>
   shirudo bpm info upatches <package> [--all]
   shirudo bpm info data <package> <member> [--json]
   shirudo bpm push <package> oci://<registry>/<repository>
                    [--keys-dir <dir> | --index-cert <certificate> --index-key <signing-key>]
                    [--new-index]
   shirudo bpm build [<context>] --version <version> [--file <beefile>]
                     [--keys-dir <dir>] [--vmlinux <vmlinux-h>]
                     [--rodata-input <name>=<path>]...
   shirudo bpm install <source>/<name>[@<version>]
   shirudo bpm install oci://<registry>/<repository>:<tag>
   shirudo bpm upgrade
   shirudo bpm list [--json]
   shirudo bpm uninstall <name>
   shirudo bpm --list-cmds

``<package>`` is a local ``.bee`` file or an ``oci://`` reference.
``<source>`` is the name of a registered repository.

.. list-table::
   :header-rows: 1
   :widths: 26 34 14 26

   * - Subcommand
     - Runs on
     - Lock
     - Measured
   * - ``config register add``, ``remove``
     - host without a config image, refused on targets with one
     - no
     - no
   * - ``config register list``
     - target
     - no
     - no
   * - ``config update``
     - operator host, helper
     - no
     - no
   * - ``repo update``
     - target
     - yes
     - no
   * - ``tree sync``
     - target
     - yes
     - yes
   * - ``tree append``
     - operator host, helper
     - no
     - no
   * - ``key add``
     - host without a config image, refused on targets with one
     - no
     - no
   * - ``key fingerprint``, ``key list``
     - any host
     - no
     - no
   * - ``pull``, ``info``
     - any host
     - no
     - no
   * - ``push``, ``build``
     - operator host, helper
     - no
     - no
   * - ``install``, ``upgrade``, ``uninstall``
     - target
     - yes
     - yes
   * - ``list``
     - target
     - no
     - no

The lock is ``/var/lib/shirudo/locks/bpm.lock``. A locked subcommand waits
for it. The helper subcommands execute ``shirudo-build`` (see
:doc:`shirudo`). ``shirudo bpm --help`` and ``--list-cmds`` show ``build``
and ``push`` only where the helper resolves. Elsewhere they are unknown
subcommands. ``config update`` and ``tree append`` always execute the
helper and fail with 127 without it.

Subcommand names after ``bpm`` and ``bpm key`` may be abbreviated (see
:doc:`shirudo`). The words after ``config``, ``repo`` and ``tree`` may
not.

config register
---------------

Repositories are registered per host in
``/etc/shirudo/bpm/registries.d/<source>.conf``. On a target with a config
image, the image's ``etc/shirudo/bpm/registries.d/`` is used instead, and
``add`` and ``remove`` are refused with:

.. code-block:: none

   image mode: change repository definitions and keys in a signed config image, then run `shirudo image update`

- ``add`` checks that the endpoint is ``oci://<host>[:<port>]`` without a
  path, checks ``--index-repository`` and that ``--cert`` is a
  certificate, and refuses any other option. It copies the certificate to
  ``/etc/shirudo/bpm/keys/<source>.der`` and writes the source file.
- ``list`` prints the registered source names, one per line.
- ``remove`` and ``rm`` delete the source file and its certificate.

The key file verifies the signed index of the repository
(:doc:`/reference/formats/bpm-formats`).

config update
-------------

``config update`` builds the next version of a package without
compiling it. For each upatch of the base package that declares
``.rodata`` inputs, it checks that the operator's key signed it, runs
the Beefile's ``update`` command for each input to produce the new
``.rodata`` (``--rodata-input`` replaces an input file), signs the upatch
again and signs a new unload directive for it. The base package must be
signed by the same key and declare ``.rodata`` inputs, and ``--version``
must be a SemVer 2.0.0 version greater than its version. Without ``--file``, the Beefile and the
commands it names come from the base package and run on the operator
host: take base packages only from sources you trust. The output is
``<name>-<version>.bee`` in the current directory. Options take their
value as the next argument only.

repo update
-----------

``repo update`` fetches each source's configured signed index, or the index
for ``<source>`` alone, verifies it with the source's key file and caches it in
``/var/lib/shirudo/bpm/repos/<source>/index.json``. A source that fails
does not stop the others, and the exit status is then 1.

tree sync
---------

``tree sync`` applies the signed upatch tree that
``etc/shirudo/bpm/upatch-tree.conf`` of the config image, or
``/etc/shirudo/bpm/upatch-tree.conf`` without one, names (``endpoint``
and ``reference``). Without that file it exits with 0 at once, without
reading its options.

#. It fetches the publication and checks its tree ID, generation, parent
   and sequence numbers against the state in
   ``/var/lib/shirudo/bpm/upatch-tree/state.json``.
#. For each new operation whose selector matches the node labels
   (``etc/shirudo/node.labels`` of the config image, or
   ``/etc/shirudo/node.labels``), it fetches and verifies the artifact,
   loads (``add``) or unloads (``delete``) it, extends the register with
   a tree event and records the new projection root.
#. It prints a JSON report to standard output, or to ``--report``.

With ``--dry-run``, it reports which operations would apply and changes
nothing. An ``add`` whose kprobe target module is not loaded is skipped
and recorded as ``skipped: module not loaded``.

tree append
-----------

``tree append`` publishes the ``[upatches.tree]`` entries of a built
package as the next operations of the signed tree at
``<repository>:<reference>`` and prints ``oci://<registry>/<repository>:<reference>
<digest>``. Its options take the value as the next argument or after
``=``:

.. list-table::
   :header-rows: 1
   :widths: 20 30 50

   * - Option
     - Default
     - Description
   * - ``--keys-dir``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Keys directory.
   * - ``--key``, ``--cert``
     - from the keys directory
     - Signing key and certificate.
   * - ``--previous-cert``
     - the signing certificate
     - Certificate that verifies the existing publication. Use the old
       certificate when the next publication will be signed by a new key.
       It does not change the certificate used to sign the new publication.
   * - ``--tree-id``
     - the existing tree's, else the package name
     - Tree ID. It must match the existing tree.
   * - ``--reference``
     - ``stable``
     - Tag of the tree publication.
   * - ``--op``
     - ``add``
     - ``add`` or ``delete``.

key
---

- ``key fingerprint`` prints the SHA-256 fingerprint of a certificate's
  public key (SPKI). The argument is a DER certificate, a ``.bee`` package
  (its ``cert.der``) or an ``oci://`` package reference.
- ``key add`` prints the same fingerprint and installs the certificate in
  ``/var/lib/shirudo/keys/<fingerprint>.der``. When
  ``/var/lib/shirudo/keys/cert.der`` does not exist, it links ``cert.der``
  to the new file, which makes it the host's primary BPF signing
  certificate. When ``cert.der`` exists with another public key, ``add``
  refuses with ``EPERM``. On a target with a config image ``add`` is
  refused.
- ``key list`` prints the fingerprints of the certificates in
  ``/var/lib/shirudo/keys`` under the heading ``Package certificates:``,
  or ``none``. With ``--json`` it prints one object with ``schema`` and
  ``fingerprints``.

``key add`` with an ``oci://`` reference installs the certificate the
registry serves. Run ``key fingerprint`` on the same reference first and
compare the result with a fingerprint you obtained out of band.

pull and info
-------------

``pull`` downloads the package layer of an ``oci://`` reference into a
new file in the current directory and checks its digest against the
manifest. The registry chooses the layer title without a signature, so
the file takes that title only when it is a package name ending in
``.bee``, and is named ``<name>-<tag>.bee`` otherwise. ``pull`` never
replaces a file: when one of that name exists, it fails with ``bpm
pull: File exists``, so remove or rename the old one first.

``info`` prints the ``README.md`` of a package. ``info upatches`` lists
its ``upatches/*.upatch`` members, with ``--all`` also the
``.unload.upatch`` directives. ``info data`` decodes the initial
``.rodata`` of one member through its BTF types, with ``--json`` as JSON.
None of them checks the package signature, so each shows a control
character, and a byte that starts no UTF-8 character, as ``?``: in the
``README.md`` all but tab, line feed and a carriage return before a line
feed, in a member or upatch name all of them. ``info data`` refuses a
``.rodata`` whose BTF names a variable or a type with anything but
printable ASCII, and without ``--json`` also a member or an enumerator,
or spells a type through a function prototype or through a chain of
more than 32 modifiers, pointers and arrays. Without ``--json`` it also
refuses a ``.rodata`` whose types nest more than eight deep, typedefs
and modifiers counted, or whose dump would print more than 1048576
values; with ``--json``, one whose structs and arrays nest more than
eight deep or whose JSON would exceed 8 MiB.

push
----

``push`` publishes a ``.bee`` file to ``oci://<registry>/<repository>``
(no tag) and prints ``oci://<registry>/<repository>:<version>``. With
``--keys-dir``, or ``--index-cert`` and ``--index-key`` together, it also
adds the package to the registry's signed index
``<namespace>/bpm-index:stable``, signed with that key. The namespace is
derived from the package repository path. Without signing options only the
package is published. ``push`` does not read ``SHIRUDO_KEYS_DIR``. Its
options take the value as the next argument or after ``=``.

``push`` refuses a namespace without an index unless ``--new-index`` is
given, and refuses ``--new-index`` where an index exists. The operator
keeps no state, so a registry that answers that it has no index cannot
be told from one that never had any, and the index signed then would
leave out every package listed before. Pass ``--new-index`` for the first
package of a namespace alone.

build
-----

``build`` builds and signs a package from a Beefile
(:doc:`/upatches/publish/beefile`):

- The Beefile is ``--file``, else ``<context>/Beefile``, with
  ``<context>`` defaulting to the current directory.
- The keys directory is ``--keys-dir`` (a leading ``~`` is expanded), else
  ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``.
- ``vmlinux.h`` is ``--vmlinux``, else ``./vmlinux.h`` or
  ``./vendor/linux/vmlinux.h`` in the current directory, else the search
  of :doc:`build` in the Beefile's directory.
- ``--rodata-input <name>=<path>`` replaces a ``.rodata`` input file of
  the Beefile. ``<name>`` is the file's base name up to the first dot
  (``watch`` for ``watch.list``). It is repeatable, once per name.
- ``--version`` is a SemVer 2.0.0 version, such as ``1.2.0`` or
  ``1.2.0-rc.1``.
- Every upatch is compiled in the Beefile's directory and signed.
- The output is ``<name>-<version>.bee`` in the current directory, and
  ``build`` prints its path.

Options take the value as the next argument or after ``=``, except
``--rodata-input``.

install, upgrade, uninstall and list
------------------------------------

``install <source>/<name>[@<version>]`` takes the package from the index
cached by ``repo update``: the given version, else the greatest. ``install
oci://<registry>/<repository>:<tag>`` takes the package directly, with the
tag as its version and the source ``direct``. The manifest is then fetched
by tag and not checked against a digest. ``install`` does nothing when a
package of that name is installed, whatever its version.

For each package ``install`` and ``upgrade``:

#. Check the manifest digest and the package's digest and size against
   the index.
#. Extract the package to
   ``/var/lib/shirudo/bpm/packages/<name>/<version>``.
#. Require the package's ``cert.der`` to hold the same public key as
   ``/var/lib/shirudo/keys/cert.der``.
#. Load each ``upatches/*.upatch`` in name order, as ``upatch load
   --no-precheck`` does, each load measured.
#. Record the package in ``/var/lib/shirudo/bpm/state.json``.

``upgrade`` takes no argument. For every package not installed ``direct``
it installs the greatest version in the cached index when that version is
greater than the installed one: it unloads the old version with its
directives, loads the new one and restores the old one when that fails.
``upgrade`` fetches no index itself. ``shirudo-bpm-repo-update.timer`` runs
``repo update`` and then ``upgrade`` at boot and 60 seconds after each
run, so a new version in a registered index reaches every target that
runs the timer.

``uninstall <name>`` applies the package's shipped unload directives in
reverse name order, each measured, removes the package directory and
drops it from the state.

``list`` prints the installed packages under the heading ``Installed
packages:`` as a table with the columns ``NAME``, ``VERSION`` and
``SOURCE``, or ``none``. With ``--json`` it prints one object with
``schema`` and ``packages``, a list of ``name``, ``version`` and
``source``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Success, or ``tree sync`` without a configured tree.
   * - 1
     - Failure, printed as ``bpm <action>: <error>``. Also the usage
       errors of ``build``, ``config update``, ``tree append`` and
       ``tree sync``, and ``config register add`` or ``remove`` and
       ``key add`` on a target with a config image.
   * - 2
     - A usage error of the other subcommands, an unknown subcommand, and
       without a message: ``repo`` without ``update``, ``repo update``
       with more than one source, ``tree sync`` with more than three
       arguments, ``upgrade`` with an argument, ``install`` without
       exactly one reference, and an unknown ``config`` action.
   * - 127
     - A helper subcommand cannot execute ``shirudo-build``.

Files and environment
---------------------

- ``/etc/shirudo/bpm/registries.d/``, ``/etc/shirudo/bpm/keys/``,
  ``/etc/shirudo/bpm/upatch-tree.conf``, ``/etc/shirudo/node.labels``, or
  the same paths in the config image
- ``/var/lib/shirudo/bpm/``: ``repos/``, ``packages/``, ``staging/``,
  ``state.json`` and ``upatch-tree/``, and
  ``/var/lib/shirudo/locks/bpm.lock``
- Registry access: ``BPM_OCI_USERNAME`` and ``BPM_OCI_PASSWORD``,
  ``BPM_OCI_BEARER_TOKEN``, ``REGISTRY_AUTH_FILE``, ``DOCKER_CONFIG`` and
  ``~/.docker/config.json``, ``BPM_OCI_SCHEME`` (``https`` or ``http``),
  ``BPM_OCI_CA_FILE``. The timer services read them from
  ``/etc/shirudo/bpm/environment``. See :doc:`/reference/environment`

Examples
--------

On the operator host, build a package and publish it with its index
entry:

.. code-block:: console

   operator$ shirudo bpm build ./example-shield --version 1.0.0 --keys-dir ~/shirudo-keys
   operator$ shirudo bpm push ./example-shield-1.0.0.bee oci://quay.io/example/example-shield --keys-dir ~/shirudo-keys

On a target, refresh the indexes and install a pinned version:

.. code-block:: console

   target# shirudo bpm repo update
   target# shirudo bpm install example/example-shield@1.0.0

List the packages of a target without any:

.. code-block:: console

   target# shirudo bpm list
   Installed packages:
     none

Preview a tree sync:

.. code-block:: console

   target# shirudo bpm tree sync --dry-run --report=/tmp/tree.json

Print the fingerprint of the certificate a package carries:

.. code-block:: console

   operator$ shirudo bpm key fingerprint ./example-shield-1.0.0.bee

Related
-------

- :doc:`/operate/run/deliver-packages`
- :doc:`/upatches/publish/publishing`
- :doc:`/upatches/publish/beefile`
- :doc:`/reference/formats/bpm-formats`
- :doc:`/reference/systemd-units`
