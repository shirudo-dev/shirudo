..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Beefile reference
=================

A Beefile describes a package: its name, the files it ships, the upatches
``shirudo bpm build`` compiles and signs into it, and the entries
``shirudo bpm tree append`` publishes to an upatch tree. ``bpm build``
reads ``<context>/Beefile``, or the file given with ``-f``, and treats
the directory that holds it as the package directory. Every path in the
Beefile is relative to that directory. The package archives the Beefile
unchanged as its ``Beefile`` member. :doc:`/reference/cli/bpm` lists the
command options and :doc:`/reference/formats/bpm-formats` the archive
format.

Syntax
------

A Beefile is a small subset of TOML, read line by line.

- Each line holds one table header, one ``key = value`` pair, a comment
  or nothing.
- A value is a quoted string or an array of quoted strings on the same
  line. A ``"..."`` string takes the escapes ``\n``, ``\r``, ``\t``,
  ``\\`` and ``\"``; a ``'...'`` string takes none.
- ``#`` starts a comment outside a string.
- Numeric values are accepted for policy bit masks; booleans, inline
  tables and values that span lines are not supported.
- ``[[upatches.rodata]]``, ``[[upatches.policy]]`` and the
  ``[upatches.tree]`` tables belong to the
  ``[[upatches]]`` entry above them. Write an entry's own keys before its
  first sub-table: a key after ``[upatches.tree]`` belongs to that table.

``bpm build`` reports every error in the file, of syntax or of content,
as ``bpm build: <file> is not a valid Beefile``, without a line number.

Keys
----

``[package]``
~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 18 14 10 58

   * - Key
     - Type
     - Required
     - Rules
   * - ``name``
     - string
     - yes
     - The package name: 1 to 127 characters of letters, digits, ``.``,
       ``_`` and ``-``, starting with a letter or a digit. The archive is
       ``<name>-<version>.bee``.
   * - ``description``
     - string
     - no
     - Read and ignored.
   * - ``license``
     - string
     - no
     - Read and ignored.
   * - ``authors``
     - array of strings
     - no
     - Read and ignored.

A ``README.md`` in the package directory is added to the package, and
``shirudo bpm info`` prints it.

``[[files]]``
~~~~~~~~~~~~~

One table per file to ship as it is: headers, generator programs, lists,
reproducers.

.. list-table::
   :header-rows: 1
   :widths: 18 14 10 58

   * - Key
     - Type
     - Required
     - Rules
   * - ``source``
     - string
     - yes
     - A regular file inside the package directory. Not absolute, no
       ``..`` component, and its real path must not leave the directory.
   * - ``target``
     - string
     - no
     - The member path in the package. Default: ``source``. Not absolute,
       no empty, ``.`` or ``..`` component.

``[[upatches]]``
~~~~~~~~~~~~~~~~

One table per upatch to build. ``bpm build`` compiles a ``.bpf.c``,
signs the object into a load artifact and generates its unload directive
from the artifact's payload digest, so a package always ships both.

.. list-table::
   :header-rows: 1
   :widths: 18 14 10 58

   * - Key
     - Type
     - Required
     - Rules
   * - ``source``
     - string
     - yes
     - A ``.bpf.c``, ``.bpf.o`` or ``.o`` file inside the package
       directory, under the same rules as a file ``source``. The upatch
       name is its base name without ``.bpf.c``, ``.bpf.o`` or ``.o``.
       There is no key to set another name.
   * - ``type``
     - string
     - no
     - ``bpf``, the default and the only value, in any case.
   * - ``load_target``
     - string
     - no
     - The member path of the load artifact. Default:
       ``upatches/<base>.upatch``, with ``<base>`` the source's base name
       without ``.bpf.c`` or ``.bpf.o``, or without its last extension.
   * - ``unload_target``
     - string
     - no
     - The member path of the unload directive. Default:
       ``upatches/<base>.unload.upatch``.

Keep both targets directly under :src:`upatches/`. On a target, ``bpm
install`` loads every file in the package's :src:`upatches/` directory whose
name contains ``.upatch`` but not ``.unload.upatch``, in name order, and
``bpm uninstall`` applies every ``upatches/*.unload.upatch`` in reverse
name order. ``bpm upgrade`` applies the old version's unload directives
before it loads the new version, and pairs ``<x>.unload.upatch`` with
``<x>.upatch`` to restore the old version when the new one fails. An
artifact elsewhere is shipped but never loaded.

``bpm build`` compiles a ``.bpf.c`` as ``shirudo build`` does, see
:doc:`/reference/cli/build`, but in the package directory. It finds
libbpf's headers in
``./vendor/libbpf`` there, or in the operator package's
``/usr/share/shirudo/bpf/include``, and ``vmlinux.h`` at ``--vmlinux``,
then at ``./vmlinux.h`` and ``./vendor/linux/vmlinux.h`` of the directory
``bpm build`` runs in, then of the package directory, then at the
installed path. ``bpm build`` passes no extra compiler flags.

``[[upatches.rodata]]``
~~~~~~~~~~~~~~~~~~~~~~~

Generated data for one ``const`` variable in the upatch's ``.rodata``. A
generator program produces the variable's bytes from an input file at
``bpm build``, and an updater program does the same at ``bpm config
update``, which re-signs the upatch without compiling it again.

.. list-table::
   :header-rows: 1
   :widths: 18 14 10 58

   * - Key
     - Type
     - Required
     - Rules
   * - ``symbol``
     - string
     - yes
     - The variable's name in the object's BTF, at most 127 characters.
   * - ``input``
     - string
     - yes
     - The default input, a regular file inside the package directory,
       not absolute, without ``..``.
   * - ``generator``
     - array of strings
     - yes
     - The command for ``bpm build``, 1 to 16 arguments.
   * - ``update``
     - array of strings
     - yes
     - The command for ``bpm config update``, 1 to 16 arguments.

The first argument of a command that contains a ``/``, or else the
second, must be a regular file inside the package directory, such as
``["python3", "gen_watch_rodata.py"]``. shirudo runs the command without
a shell, with ``execvp``, in the package directory, and appends ``--input
<path> --symbol <symbol> --output <path>``. The program writes the
variable's raw bytes to the output file. A result whose length differs
from the variable's size fails the build.

An input is named by its file name up to the first dot: ``watch.list``
is ``watch``. ``--rodata-input <name>=<path>`` replaces the input of every
entry with that name for one build. An override for a name that no entry
has fails. Entries that share a name must name the same input.

``[[upatches.policy]]``
~~~~~~~~~~~~~~~~~~~~~~~

A policy table declares a named bit and the absolute paths whose
``security.bpf.shirudo.policy`` xattrs this upatch labels. The builder
embeds the entries in the signed upatch metadata.

.. code-block:: toml

   [[upatches.policy]]
   id = "apache"
   bit = 0x1
   paths = ["/usr/local/apache", "/usr/bin/apache"]

``id`` maps to one one-hot 64-bit mask. Repeating the same ID and mask in
other upatches extends that policy; an ID cannot change masks, and two
different IDs cannot use the same mask in one package. Paths may name
non-executable files.

The generator and the updater run on the operator host with the
operator's rights. The target receives only the signed result. Without
``-f``, ``bpm config update`` takes the Beefile and the updater from the
base package and runs them. It also trusts the base package's unsigned
header to locate ``.rodata`` before it re-signs, so run it only on a base
package you built or verified yourself.

``[upatches.tree]``
~~~~~~~~~~~~~~~~~~~

Optional. Present when ``bpm tree append`` is to publish the upatch as a
tree operation.

.. list-table::
   :header-rows: 1
   :widths: 18 14 10 58

   * - Key
     - Type
     - Required
     - Rules
   * - ``id``
     - string
     - yes
     - The operation's identity across generations. A valid upatch name,
       and equal to the upatch's name, the source's base name:
       ``bpm tree append`` refuses an artifact whose name differs, and so
       does the target.
   * - ``load_artifact``
     - string
     - no
     - The member that an ``add`` publishes. Default: ``load_target``.
   * - ``unload_artifact``
     - string
     - no
     - The member that a ``delete`` publishes. Default:
       ``unload_target``.

``[upatches.tree.selector]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional. Says where the operation applies. Every key holds an array of 1
to 16 accepted values, and each key may appear once.

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Key
     - Matches when
   * - ``kernel_release_prefix``
     - ``uname -r`` starts with a value and continues with ``.``, ``-`` or
       nothing: ``7.2`` matches ``7.2.0`` and ``7.2-rc1``, not ``7.20``.
   * - ``kernel_build_id``
     - the running kernel's GNU build ID from ``/sys/kernel/notes``, in
       lowercase hex, equals a value. A kernel without one never matches.
   * - ``architecture``
     - ``uname -m`` equals a value, such as ``x86_64``, ``aarch64`` or
       ``riscv64``.

``[upatches.tree.selector.kconfig]``
    Up to 64 keys, each a Kconfig option, once, with its accepted values,
    such as ``CONFIG_IPV6 = ["y", "m"]``. An option that is not set matches
    ``"n"``. The target reads ``/proc/config.gz`` and, when that is
    missing or names none of the options, ``/boot/config-<release>``. A
    target with neither does not match.
``[upatches.tree.selector.labels]``
    Up to 64 keys, each a node label, once, with its accepted values, such
    as ``env = ["prod", "canary"]``. The target reads its labels from the
    signed config image's ``etc/shirudo/node.labels``. A target without
    labels does not match.

A target matches a selector when it matches every key given, and a key
when it matches one of its values. An entry without a selector applies
everywhere. A target that does not match an operation passes over it and
never comes back to it, also after a kernel upgrade or a label change.

Unknown keys and tables
-----------------------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Where
     - Result
   * - an unknown key in ``[package]``, ``[[files]]``, ``[[upatches]]``,
       ``[[upatches.rodata]]`` or ``[upatches.tree.selector]``
     - refused
   * - an unknown array of tables, ``[[name]]``
     - refused
   * - an unknown table under ``upatches.tree``
     - refused, because a selector the builder cannot read would widen
       the rollout
   * - an unknown key in ``[upatches.tree]``
     - ignored, as metadata for newer publishers
   * - a key before the first table, or in a table with any other name
     - ignored

Limits and reserved names
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Limit
     - Value
   * - ``[[files]]`` tables
     - 128
   * - ``[[upatches]]`` tables
     - 128
   * - ``[[upatches.rodata]]`` tables per upatch
     - 16
   * - arguments per ``generator`` or ``update`` command
     - 16
   * - values per selector key
     - 16
   * - keys in each of ``kconfig`` and ``labels``
     - 64
   * - length of a string in a selector or command
     - 255 bytes
   * - package version, ``--version``
     - 1 to 127 characters of letters, digits, ``.``, ``_``, ``-`` and
       ``+``, starting with a letter or a digit
   * - member path including ``<name>-<version>/``
     - 99 bytes, the limit of a ustar name
   * - ``.bee`` file
     - 256 MiB per member file

Every member path must be unique. ``Beefile``, ``README.md``,
``cert.der`` and ``build-environment.json`` are reserved for the members
``bpm build`` writes itself. A member path longer than the ustar limit
fails the build with ``bpm build: File name too long``.

Example
-------

:src:`upatches/kernel-obs/Beefile` declares one upatch with generated
``.rodata`` and ships its generators:

.. literalinclude:: ../../../upatches/kernel-obs/Beefile
   :language: toml

:src:`upatches/kernel-cve/kernel-cve.bee` breaks these rules and is not a
model. Two of its load targets make member paths longer than 99 bytes
with any version, so ``bpm build`` fails. Its tree ids name the CVE
directories while its upatch names are the detectors' base names, so
``bpm tree append`` would refuse every entry. And its
``unload_artifact`` paths name members the package does not have.

Related
-------

- :doc:`/upatches/publish/publishing` for building, pushing and appending a
  package
- :doc:`/reference/cli/bpm` for ``bpm build`` and ``bpm config update``
- :doc:`/reference/formats/bpm-formats` for the archive, the index and the
  tree
