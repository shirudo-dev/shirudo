..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

Beefile
=======

A Beefile describes a package: its name, the files it ships, the upatches
``shirudo bpm build`` compiles and signs into it, and the entries
``shirudo bpm tree append`` publishes to a upatch tree. ``bpm build``
reads ``<context>/Beefile``, or the file given with ``--file``, and treats
the directory that holds it as the package directory. Every path in the
Beefile is relative to that directory. The package archives the Beefile
unchanged as its ``Beefile`` member. :doc:`/reference/cli/bpm` lists the
command options and :doc:`bpm-formats` the archive format.

Overview
--------

Every table a Beefile may hold, the keys each takes and how many of it
a package may have:

.. code-block:: none

   [package]                          once
       name                           package name
       description, license, authors  read and ignored
   [[files]]                          up to 128
       source, target                 a file shipped as it is
   [[upatches]]                       up to 128
       source                         the BPF program, names the upatch
       type                           bpf or java
       load_target, unload_target     where the artifacts go
     [[upatches.rodata]]              up to 16 per upatch
       symbol, input, generator,      generated .rodata
       update
     [[upatches.policy]]              up to 64 per upatch
       id, bit, paths                 signed policy labels
     [upatches.tree]                  once per upatch
       id                             the operation's identity
       load_artifact, unload_artifact what add and delete publish
       fixes                          advisories the upatch fixes
     [upatches.tree.selector]         once per upatch
       kernel_release_prefix,         kernel and machine
       kernel_build_id, architecture
     [upatches.tree.selector.kconfig] Kconfig option values
     [upatches.tree.selector.labels]  node labels

Syntax
------

A Beefile is a small subset of TOML, read line by line. ``bpm build``
reports every error in the file, of syntax or of content, as ``bpm
build: <file> is not a valid Beefile``, without a line number. For a
``fixes`` it refuses, a ``Beefile: fixes ...`` line before that one says
what is wrong with the list.

File
~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Element
     - Rule
   * - Line
     - One table header, one ``key = value`` pair, a comment or nothing.
   * - String
     - ``"..."`` takes the escapes ``\n``, ``\r``, ``\t``, ``\\`` and
       ``\"``; ``'...'`` takes none.
   * - Array
     - Of quoted strings, on the same line.
   * - Number
     - Only for a policy ``bit``, read as hexadecimal.
   * - Comment
     - ``#`` outside a string, to the end of the line.
   * - Not supported
     - Booleans, inline tables and values that span lines.

A tree id or selector value holding a control character, as the first
three escapes spell, is refused by ``bpm tree append``, as no node could
read the publication.

.. code-block:: toml

   [package]
   name = "xfs-fix"                    # a comment
   authors = ['Ops team', "On-call \"A\""]

Nesting
~~~~~~~

``[[upatches.rodata]]``, ``[[upatches.policy]]`` and the
``[upatches.tree]`` tables belong to the ``[[upatches]]`` entry above
them. Write an entry's own keys before its first sub-table: a key after
``[upatches.tree]`` belongs to that table.

.. code-block:: toml

   [[upatches]]
   source = "a.bpf.c"                  # entry key: before any sub-table

   [upatches.tree]
   id = "a"                            # belongs to the tree table of a

   [[upatches]]                        # a new entry starts here
   source = "b.bpf.c"

Keys
----

``[package]``
~~~~~~~~~~~~~

Once per Beefile.

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

.. code-block:: toml

   [package]
   name = "kernel-obs"
   description = "shirudo kernel observability"
   license = "GPL-2.0 OR BSD-2-Clause"
   authors = ["Authors of shirudo"]

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

.. code-block:: toml

   [[files]]
   source = "watch.list"
   target = "watch.list"

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
       directory, or a ``.jar`` for a Java upatch, under the same rules as
       a file ``source``. The upatch name is its base name without
       ``.bpf.c``, ``.bpf.o``, ``.o`` or ``.jar``. There is no key to set
       another name.
   * - ``type``
     - string
     - no
     - ``bpf``, the default, or ``java``, in any case. A ``java`` upatch
       signs its ``.jar`` source as a Java agent (see
       :doc:`/reference/cli/build`) and takes no ``[[upatches.rodata]]``
       or ``[[upatches.policy]]``.
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

.. code-block:: toml

   [[upatches]]
   source = "kernel-obs.bpf.c"         # upatch name: kernel-obs

Keep both targets directly under ``upatches/``. On a target, ``bpm
install`` loads every file in the package's ``upatches/`` directory whose
name contains ``.upatch`` but not ``.unload.upatch``, in name order, and
``bpm uninstall`` applies every ``upatches/*.unload.upatch`` in reverse
name order. ``bpm upgrade`` applies the old version's unload directives
before it loads the new version, and pairs ``<x>.unload.upatch`` with
``<x>.upatch`` to restore the old version when the new one fails. An
artifact elsewhere is shipped but never loaded.

``bpm build`` compiles a ``.bpf.c`` as ``shirudo build`` does, see
:doc:`/reference/cli/build`, but in the package directory. It finds
libbpf's headers in ``./vendor/libbpf`` there, or in the operator
package's ``/usr/share/shirudo/bpf/include``, and ``vmlinux.h`` at
``--vmlinux``, then at ``./vmlinux.h`` and ``./vendor/linux/vmlinux.h``
of the directory ``bpm build`` runs in, then of the package directory,
then at the installed path. ``bpm build`` passes no extra compiler
flags.

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

.. code-block:: toml

   [[upatches.rodata]]
   symbol = "obs_watch_v4"
   input = "watch.list"
   generator = ["python3", "gen_watch_rodata.py"]
   update = ["python3", "gen_watch_rodata.py"]

The first argument of a command that contains a ``/``, or else the
second, must be a regular file inside the package directory, such as
``gen_watch_rodata.py`` above. shirudo runs the command without a shell,
with ``execvp``, in the package directory, and appends ``--input <path>
--symbol <symbol> --output <path>``. The program writes the variable's
raw bytes to the output file. A result whose length differs from the
variable's size fails the build.

An input is named by its file name up to the first dot: ``watch.list``
is ``watch``. ``--rodata-input <name>=<path>`` replaces the input of every
entry with that name for one build. An override for a name that no entry
has fails. Entries that share a name must name the same input.

The generator and the updater run on the operator host with the
operator's rights. The target receives only the signed result. Without
``--file``, ``bpm config update`` takes the Beefile and the updater from
the base package and runs them. It also trusts the base package's
unsigned header to locate ``.rodata`` before it re-signs, so run it only
on a base package you built or verified yourself.

``[[upatches.policy]]``
~~~~~~~~~~~~~~~~~~~~~~~

A named policy bit and the absolute paths whose
``security.bpf.shirudo.policy`` xattrs this upatch labels. The builder
embeds the entries in the signed ``SHPL`` section.

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
     - The policy's name, mapped to one one-hot 64-bit mask. Repeating
       the same ID and mask in other upatches extends that policy; an ID
       cannot change masks.
   * - ``bit``
     - number
     - yes
     - The one-hot mask, read as hexadecimal, with or without ``0x``, so
       ``bit = 10`` is ``0x10``. Two different IDs cannot use the same
       mask in one package.
   * - ``paths``
     - array of strings
     - yes
     - 1 to 16 absolute paths. A path may name a non-executable file.

.. code-block:: toml

   [[upatches.policy]]
   id = "apache"
   bit = 0x1
   paths = ["/usr/local/apache", "/usr/bin/apache"]

A policy table opts the upatch into shirudo's shared task
``shirudo_task_policy`` and socket ``shirudo_sock_policy`` maps. The
generated loader reuses both pinned maps rather than creating private
copies. The BPF source must declare the map ABI, normally by including
``policy.h`` after ``vmlinux.h`` and the libbpf headers. It also brings
``XATTR_POLICY``, the name of the xattr, for a program that reads it.
The header is installed beside the shirudo BPF headers. Declaring the
maps without policy tables leaves them as ordinary upatch-owned maps.

Signed BPF programs can write the maps, so enforcement programs must
treat them as read-only by contract. Root can give its own processes
any bit, through a file system it mounts whose executables carry the
xattr, so let a bit restrict what a task may do, never exempt it from a
rule.

``[upatches.tree]``
~~~~~~~~~~~~~~~~~~~

Optional, once per upatch. Present when ``bpm tree append`` is to
publish the upatch as a tree operation.

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
   * - ``fixes``
     - array of strings
     - no
     - The IDs of the advisories the upatch fixes: 1 to 16 IDs, each
       once and of 1 to 255 bytes of letters, digits, ``.``, ``_``,
       ``:`` and ``-``. The key may appear once.

.. code-block:: toml

   [upatches.tree]
   id = "xfs-fix"                      # source = "xfs-fix.bpf.c"
   fixes = ["EXAMPLE-0101"]

``fixes`` is a convention of the keepalive backend, which reads it to say
which nodes are exposed to an advisory. Nodes ignore it: it selects
nothing, and no target reads, checks or measures it. ``bpm build``
checks the form of each ID, not that the advisory exists, and refuses a
list that breaks the rules above, an empty list and a value that is not
an array of strings. It keeps the Beefile as written; the order of the
IDs does not matter, because the list is published in byte order.
``bpm tree append`` writes it on the operation it publishes as an
``add``, outside the operation digest, and never on a ``delete``
(:doc:`/upatches/publish/publishing`).

``[upatches.tree.selector]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Optional, once per upatch. Says where the operation applies. Every key
holds an array of 1 to 16 accepted values, and each key may appear once.

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

.. code-block:: toml

   [upatches.tree.selector]
   kernel_release_prefix = ["7.4"]
   architecture = ["x86_64", "aarch64"]

A target matches a selector when it matches every key given, including
the keys of its ``kconfig`` and ``labels`` tables, and a key when it
matches one of its values. An entry without a selector applies
everywhere. A target that does not match an operation passes over it and
never comes back to it, also after a kernel upgrade or a label change.

``[upatches.tree.selector.kconfig]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Up to 64 keys, each a Kconfig option, once, with its accepted values. An
option that is not set matches ``"n"``. The target reads
``/proc/config.gz`` and, when that is missing, is not one whole gzip
stream or names none of the options, ``/boot/config-<release>``, each of
at most 4 MiB. A target with neither does not match, and one whose
configuration cannot be read stops the sync at the operation. A line of
1024 bytes or more is skipped whole, so its option reads as not set.

.. code-block:: toml

   [upatches.tree.selector.kconfig]
   CONFIG_XFS_FS = ["y", "m"]

``[upatches.tree.selector.labels]``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Up to 64 keys, each a node label, once, with its accepted values. The
target reads its labels from the signed config image's
``etc/shirudo/node.labels``. A target without labels does not match.

.. code-block:: toml

   [upatches.tree.selector.labels]
   role = ["edge"]

Checks
------

Unknown keys and tables
~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Where
     - Result
   * - an unknown key in ``[package]``, ``[[files]]``, ``[[upatches]]``,
       ``[[upatches.rodata]]``, ``[[upatches.policy]]`` or
       ``[upatches.tree.selector]``
     - refused
   * - an unknown array of tables, ``[[name]]``
     - refused
   * - an unknown table under ``upatches.tree``
     - refused, because a selector the builder cannot read would widen
       the rollout
   * - a table name with quotes, or blanks around its dots, such as
       ``[upatches ."tree".selector]``
     - refused, for the same reason
   * - an unknown key in ``[upatches.tree]``
     - ignored, as metadata for newer publishers, unless it is
       ``selector``, quoted or dotted, such as
       ``selector.architecture = ["aarch64"]``, which is refused
   * - a key before the first table, or in a table with any other name
     - ignored

Limits and reserved names
~~~~~~~~~~~~~~~~~~~~~~~~~

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
   * - ``[[upatches.policy]]`` tables per upatch
     - 64
   * - ``paths`` per policy table
     - 16
   * - values per selector key
     - 16
   * - IDs in ``fixes``
     - 16, of 255 bytes each
   * - keys in each of ``kconfig`` and ``labels``
     - 64
   * - length of a string in a selector or command
     - 255 bytes
   * - package version, ``--version``
     - A SemVer 2.0.0 version of at most 127 characters, such as
       ``1.2.0``, ``1.2.0-rc.1`` or ``1.2.0+build.5``
   * - member path including ``<name>-<version>/``
     - 99 bytes, the limit of a ustar name
   * - ``.bee`` file
     - 256 MiB for all member files together

Every member path must be unique, and none may lie below another: a
name is a file or a directory, not both, so ``a`` and ``a/b`` do not go
into one package. ``Beefile``, ``README.md``, ``cert.der`` and
``build-environment.json`` are reserved for the members ``bpm build``
writes itself, and no member path lies below one of them either. A
member path longer than the ustar limit fails the build with ``bpm
build: File name too long``, and members of more than 256 MiB together,
or one of that size alone, with ``bpm build: the members of the package
are more than 256 MiB together, the most a target installs``: a target
unpacks no more.

Output
------

``bpm build`` writes ``<name>-<version>.bee``, a gzip-compressed ustar
archive with one top-level directory ``<name>-<version>/``.
:doc:`bpm-formats` gives the archive's rules.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Member
     - From
   * - ``Beefile``
     - This file, unchanged.
   * - ``<target>``
     - Each ``[[files]]`` entry.
   * - ``upatches/<base>.upatch``
     - Each ``[[upatches]]`` load artifact, signed, at its
       ``load_target``.
   * - ``upatches/<base>.unload.upatch``
     - Its unload directive, signed, at its ``unload_target``.
   * - ``README.md``
     - The package directory's, when it has one.
   * - ``cert.der``
     - The signing certificate.
   * - ``build-environment.json``
     - The build record.

Examples
--------

Generated data
~~~~~~~~~~~~~~

:src:`upatches/kernel-obs/Beefile` declares two upatches, one with two
generated ``.rodata`` variables, and ships the generators and their
input beside them. It has no tree entry: it is installed with ``bpm
install``.

.. literalinclude:: ../../../upatches/kernel-obs/Beefile
   :language: toml

.. code-block:: console

   operator$ shirudo bpm build upatches/kernel-obs --version 1.0.0 --keys-dir keys

The package holds ``Beefile``, ``README.md``, ``build-environment.json``,
``cert.der``, the four ``[[files]]`` members and, under ``upatches/``,
``kernel-obs.upatch``, ``kernel-obs.unload.upatch``,
``userns-unshare-counter.upatch`` and
``userns-unshare-counter.unload.upatch``.

Policy labels
~~~~~~~~~~~~~

:src:`testing/fixtures/policy-exec-graph/Beefile` declares five policy
bits, each labeling one path, which its upatch reads to decide which
executables a task may start and which sockets it may use.

.. literalinclude:: ../../../testing/fixtures/policy-exec-graph/Beefile
   :language: toml

A tree entry
~~~~~~~~~~~~

:src:`testing/fixtures/pipeline/xfs-fix/Beefile` publishes its upatch
to a tree as an operation that only nodes labeled ``role=edge`` apply,
and names the advisory it fixes.

.. literalinclude:: ../../../testing/fixtures/pipeline/xfs-fix/Beefile
   :language: toml

.. code-block:: console

   operator$ shirudo bpm build ./xfs-fix --version 1.1.0 --keys-dir keys
   operator$ shirudo bpm tree append ./xfs-fix-1.1.0.bee \
                 oci://registry.example.com/shirudo/fleet-base --keys-dir keys

Not a model
~~~~~~~~~~~

:src:`upatches/kernel-cve/kernel-cve.bee` breaks these rules. Two of its
load targets make member paths longer than 99 bytes with any version, so
``bpm build`` fails. Its tree ids name the CVE directories while its
upatch names are the detectors' base names, so ``bpm tree append`` would
refuse every entry. And its ``unload_artifact`` paths name members the
package does not have.

Related
-------

- :doc:`/upatches/publish/publishing` for building, pushing and appending
  a package
- :doc:`/reference/cli/bpm` for ``bpm build``, ``bpm tree append`` and
  ``bpm config update``
- :doc:`bpm-formats` for the archive and the index
- :doc:`upatch-tree` for the tree the ``[upatches.tree]`` entries
  publish to
