..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: All readers

shirudo
=======

``shirudo`` runs one command of the operator or the target, and hands the
operator-only commands to the ``shirudo-build`` helper.

Runs on: any host. Requires: locked process memory (``CAP_IPC_LOCK`` or a
large enough ``RLIMIT_MEMLOCK``). Changes measured state: depends on the
command.

Usage
-----

.. code-block:: none

   shirudo <command> [<args>]
   shirudo help [--list-cmds]
   shirudo --help | -h
   shirudo --list-cmds

Commands
--------

.. list-table::
   :header-rows: 1
   :widths: 18 30 52

   * - Command
     - Runs on
     - Summary
   * - :doc:`genkey`
     - operator host
     - Generate the ML-DSA-87 signing key and certificate.
   * - :doc:`build`
     - operator host, through the helper
     - Compile and sign a ``.upatch``, or sign an unload directive.
   * - :doc:`init`
     - target
     - Bring up enforcement and bind the measurement register.
   * - ``upatch``
     - target, and ``info`` on any host
     - :doc:`upatch-load`, :doc:`upatch-unload`, :doc:`upatch-list`,
       :doc:`upatch-info`, :doc:`upatch-get`, :doc:`upatch-map`.
   * - :doc:`bpm`
     - target, and the operator host for ``build``, ``push``,
       ``tree append``, ``tree show`` and ``config update``
     - Install, upgrade and remove signed packages. Build and publish
       them.
   * - :doc:`image`
     - the operator host for ``build`` and ``verify``, the target for
       ``update`` and ``status``
     - Build, verify and activate signed config images.
   * - :doc:`status`
     - any host
     - Readiness and state report.
   * - ``attest``
     - target for :doc:`evidence <attest>`, operator host for
       :doc:`attest-verify`, :doc:`attest-predict` and
       :doc:`attest-challenge`
     - TPM-signed evidence and its offline verification.
   * - :doc:`keys`
     - any host, and the operator host for ``vouch``
     - Show key material and vouch for a certificate.
   * - :doc:`version`
     - any host
     - Print the release and ``SHIRUDO_VERSION_ID``.
   * - :doc:`config`
     - any host
     - Print the effective ``shirudo.conf``.
   * - ``help``
     - any host
     - Print the command list.

Description
-----------

Every invocation goes through the same steps before the command runs:

#. Standard input, output and error that are closed are reopened on
   ``/dev/null``.
#. The process hardens itself: it drops the personality flags of its
   caller, lifts its file size and CPU time limits, disarms its interval
   timers, is not dumpable, sets ``no_new_privs``, writes no core file,
   loads no OpenSSL configuration file, resolves host names through
   ``files`` and ``dns`` only and locks all its memory with
   ``mlockall()``. When the lock fails, ``shirudo`` prints
   ``hardening: cannot lock process memory: <error>`` and exits with 1. The shipped systemd units set ``LimitMEMLOCK=infinity``.
#. ``shirudo`` resolves the command name (see below).
#. On a target where enforcement is up, the image gate runs (see below).
#. The command runs.

Progress, warning and error messages go to standard error and to syslog
with the identifier ``shirudo`` and the facility ``LOG_AUTHPRIV``, where
journald picks them up. Where standard error is the journal's own
stream, as under the systemd units, they go to syslog alone, so that the
journal holds each message once; systemd names that stream in
``JOURNAL_STREAM``. Results go to standard output. Help text goes to
standard error, except the help of the generator scripts, which goes to
standard output.

Command names
~~~~~~~~~~~~~

``shirudo`` accepts a command name in three forms, tried in this order:

#. The exact name.
#. A unique prefix: ``shirudo stat`` runs ``status``. A prefix that
   matches more than one command (``shirudo i``) prints the matches and
   exits with 1.
#. An input that starts with a command name: ``shirudo initialize`` runs
   ``init``.

An unknown name prints ``'<input>' is not a shirudo command.``, a list of
similar names, and exits with 1. The subcommands of ``upatch``, ``keys``,
``attest``, ``bpm`` and ``bpm key`` resolve the same way. The subcommands
of ``image``, the actions of ``bpm config register`` and the words
``repo update``, ``tree sync``, ``tree append`` and ``tree show`` must be
spelled out.

``shirudo --list-cmds`` and ``shirudo help --list-cmds`` print the
command names one per line. Bash completion reads them from there.

Option forms
~~~~~~~~~~~~

Every command parses its options by the same rules. An option that
takes a value takes it after an equals sign or as the next argument:
``--cert=cert.der`` and ``--cert cert.der`` are the same. An unknown
option, an option given twice where it does not repeat, a value missing
or empty, and an argument the command does not take are usage errors:
the command prints one line, ``<command>: <what is wrong>``, with the
closest option names after an unknown one, and exits with 2. ``--``
ends the options, ``-h`` and ``--help`` print the command's help,
``--list-opts`` prints its options one a line, a value's placeholder
after a tab, and ``--list-cmds`` its subcommands, none where it has
none. The bash completion reads both. ``upatch map
--json=<path>`` takes its path after the equals sign only, as ``--json``
alone prints the JSON. ``image build`` hands its arguments to
``shirudo-gen-verity``, which takes each value as the next argument
only. The same function has the same name on every command:
a file to write is ``-o <path>`` or ``--output <path>``, a certificate
file is ``--cert``, a signing key ``--key``, the directory that holds
both ``--keys-dir``, a Beefile ``--file``, and ``--json`` prints the
JSON form wherever a command has one.

Runtime binary
~~~~~~~~~~~~~~

On a production target, run every target command with the binary on the
authenticated runtime image, ``/run/shirudo/runtime/usr/bin/shirudo``. A
dynamically linked build runs through the loader and libraries on the
same image:

.. code-block:: none

   /run/shirudo/runtime<interpreter> --inhibit-cache --library-path <library-path> \
       /run/shirudo/runtime/usr/bin/shirudo <command> [<args>]

``<interpreter>`` and ``<library-path>`` are the values
``shirudo-gen-runtime`` prints when it builds the image (see
:doc:`gen-tools`). The examples in this reference show the runtime binary
as ``shirudo``.

The LSM grants runtime authority only to a process that executed the
authenticated runtime binary (see :doc:`/internals/seal`). Any other copy
of the binary, the one in ``/usr/bin`` included, is refused before the
command runs:

.. code-block:: console

   target# /usr/local/bin/shirudo status
   shirudo: image state: Permission denied

All six shipped root-filesystem services invoke
``/run/shirudo/runtime/usr/bin/shirudo`` directly (see
:doc:`/reference/systemd-units`). For a dynamically linked binary,
``shirudo-gen-runtime --unit-dir`` generates drop-ins for all six
services; ``--unit-output`` writes the ``shirudo.service`` drop-in
alone.

Image gate
~~~~~~~~~~

Before every command except ``init``, ``genkey``, ``build``, ``help``,
``version``, ``image build`` and ``image verify``, ``shirudo`` checks the
state of the target:

- On a host where enforcement is not up and the identity pin
  ``/run/shirudo/bpffs/identity`` does not exist or cannot be read, the
  gate does nothing. Operator hosts are in this state.
- Where enforcement is up, the gate reads the frozen identity, loads the
  authenticated bootstrap and runtime settings, and then refuses with
  ``EPERM``:

  - any argument that begins with ``--keys-dir``, ``--cert`` or
    ``--tcti``,
  - any of the environment variables ``SHIRUDO_KEYS_DIR``,
    ``SHIRUDO_TPM_TCTI``, ``SHIRUDO_TPM_OWNER_AUTH``,
    ``SHIRUDO_EVENTLOG_PATH``, ``SHIRUDO_EVENTLOG_PENDING_PATH``,
    ``SHIRUDO_INITRD_RELEASE`` and ``SHIRUDO_SYSROOT``, with
    ``bootstrap override <name> is forbidden``.

- The gate then requires a config activation that is complete and
  consistent with its records. While an activation is pending or cannot
  be verified, only ``status`` runs.

A refusal prints ``shirudo: image state: <error>`` and exits with 1.

Operator helper
~~~~~~~~~~~~~~~

``build``, ``keys vouch``, ``image build``, ``image verify``, ``bpm
build``, ``bpm push``, ``bpm tree append``, ``bpm tree show`` and ``bpm
config update`` run
in the separate ``shirudo-build`` binary, which the operator package
installs. ``shirudo`` executes the first of:

#. ``$SHIRUDO_BUILD``. An empty value is refused.
#. The path compiled in from ``libexecdir``:
   ``/usr/libexec/shirudo/shirudo-build`` in the distribution packages,
   ``/usr/local/libexec/shirudo/shirudo-build`` after ``make install``.
   ``shirudo build --help`` prints the path this binary uses.
#. ``shirudo-build`` on ``PATH``.

When the helper cannot be executed, ``shirudo`` prints why and exits with
127. ``shirudo bpm --help`` lists ``build`` and ``push`` only when the
helper resolves.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The command succeeded.
   * - 1
     - The command failed or was refused, the image gate refused it, the
       command name is unknown or ambiguous, or ``shirudo`` ran without
       a command.
   * - 2
     - Most commands: a usage error. Several commands use 1 and 2
       differently. Each command page lists its own.
   * - 127
     - The ``shirudo-build`` helper is missing or cannot be executed.

``shirudo status`` exits with 0 whatever the verdict. Read the verdict
from its output, not from the exit status. The failure categories that
``upatch load``, ``upatch unload`` and the reports name are listed in
:doc:`/reference/failure-categories`.

Files and environment
---------------------

- ``SHIRUDO_BUILD``: the helper to execute
- ``PATH``: searched for ``shirudo-build`` last
- ``/run/shirudo/bpffs/identity``: the identity pin the image gate reads

:doc:`/reference/environment` and :doc:`/reference/files` list every
variable and path.

Examples
--------

Print the version of any copy of the binary. ``version`` does not go
through the image gate:

.. code-block:: console

   $ shirudo version
   shirudo (58d3fa7-dirty-rc0, "Social BPF Coding")
   version-id: 58b05ab35a2bcefaa649faf15f8c6be0211e24cea710450c1a29298c3b5c7de0

Run an operator command with a helper from a checkout:

.. code-block:: console

   operator$ SHIRUDO_BUILD=$PWD/tools/shirudo-build/shirudo-build shirudo build fix.bpf.c

Related
-------

- :doc:`/concepts/operator-and-target`
- :doc:`/reference/cheat-sheet`
- :doc:`/reference/failure-categories`
