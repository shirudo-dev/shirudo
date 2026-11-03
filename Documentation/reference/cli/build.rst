..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: upatch authors

shirudo build
=============

Compile and sign a BPF program into a ``.upatch`` artifact, or sign an
unload directive for a loaded upatch.

Runs on: operator host, without the image gate. Requires: the
``shirudo-build`` helper, the signing key and certificate, and for a
``.bpf.c`` input clang 23 and a ``vmlinux.h``. Changes measured
state: no.

Usage
-----

.. code-block:: none

   shirudo build <input> [-o <output>] [--name <name>]
                 [--keys-dir <dir> | --keys-dir=<dir>]
                 [--key <signing-key>] [--cert <certificate>]
                 [--vmlinux <vmlinux-h>] [--extra-cflags <flags>]
                 [--emit-artifacts]
                 [--attach-upatch <target-upatch>
                  --attach-object <target-object>]
   shirudo build --unload <name> [-o <output>] [--payload-sha256 <digest>]
                 [--keys-dir <dir> | --keys-dir=<dir>]
                 [--key <signing-key>] [--cert <certificate>]
   shirudo build --help
   shirudo-build --help

Every option except ``--keys-dir`` takes its value as the next argument.
The form ``--option=<value>`` is refused as an unknown option, except
``--keys-dir=<dir>``. Options and the input may come in any order.

``shirudo build`` executes the ``shirudo-build`` helper with the same
arguments (see :doc:`shirudo` for how it finds the helper).
``shirudo build --help`` prints a short summary and the helper path.
``shirudo-build --help``, or ``--help`` after any other argument, prints
the helper's full option list.

Description
-----------

Building a upatch
~~~~~~~~~~~~~~~~~

#. The helper resolves the signing key and the certificate: ``--key`` and
   ``--cert``, else ``signing_key.pem`` and ``cert.der`` in the keys
   directory, which is ``--keys-dir``, else ``$SHIRUDO_KEYS_DIR``, else
   ``/var/lib/shirudo/keys``. The key must be a regular file with mode
   0600 and the certificate readable.
#. It selects the output: ``-o``, else the input path with a trailing
   ``.c`` or ``.o`` replaced by ``.upatch``, beside the input
   (``fix.bpf.c`` becomes ``fix.bpf.upatch``).
#. For a ``.bpf.c`` input, it finds ``vmlinux.h``: ``--vmlinux``, else
   ``./vmlinux.h``, else ``./vendor/linux/vmlinux.h``, else the installed
   ``vmlinux.h`` (``/usr/share/shirudo/vmlinux.h`` in the operator
   package, ``/usr/local/share/shirudo/vmlinux.h`` after ``make
   install``). It then runs ``/usr/bin/clang -target bpf -mcpu=v4
   -fno-jump-tables -O2 -g -Wall -Wextra -Wshadow -Wtype-limits`` with
   the ``vmlinux.h`` directory, the libbpf headers and the shirudo BPF
   headers on the include path, plus ``--extra-cflags``. ``-mcpu=v4``
   selects BPF instruction set v4, the newest clang knows and one every
   target kernel runs. ``-fno-jump-tables`` keeps a ``switch`` in
   branches, where clang would otherwise read its results from a table in
   ``.rodata`` at an offset the verifier cannot bound. The clang path is fixed when the helper is built,
   ``/usr/lib/llvm-23/bin/clang`` in the Debian package, and ``PATH`` is
   not searched. The object goes to a temporary file in
   ``/tmp``, or with ``--emit-artifacts`` beside the output.
#. A ``.bpf.o`` or ``.o`` input is packaged as it is. Any other input is
   refused.
#. It names the upatch: ``--name``, else the input file name without
   ``.bpf.c``, ``.bpf.o`` or ``.o``.
#. It generates the loader for the object, signs it with the key and
   writes the artifact. The detached CMS signature covers the loader
   instructions and the loader's data, which hold the payload and the
   signed sections: the name, the attach metadata and any decoders (see
   :doc:`/reference/formats/upatch-format`).

The helper prints ``wrote <output> (insns=<n> sig=<n> data=<n>
sections=<n> maps=<n> progs=<n> decoders=<n> name=<name>)``.

Signing an unload directive
~~~~~~~~~~~~~~~~~~~~~~~~~~~

With ``--unload <name>``, the helper takes no input. It signs the
prebuilt unload program together with ``<name>`` and the expected payload
digest:

#. The expected digest is ``--payload-sha256``, 64 hexadecimal
   characters. Read it from the artifact with ``upatch info --json`` (key
   ``payload_sha256``).
#. Without ``--payload-sha256``, the helper reads the digest from
   ``/var/lib/shirudo/upatches/<name>.upatch`` on the host it runs on.
   Without that file it signs 32 zero bytes and prints a warning.
#. The output is ``-o``, else ``<name>.unload.upatch`` in the current
   directory.

A target applies a directive only to an upatch whose loaded payload
digest equals the signed one (:doc:`upatch-unload`). The helper's warning
and ``--help`` say that an all-zero digest makes the target skip that
check. It does not: the target compares the digests and refuses a
directive with a zero digest with ``payload_mismatch``. Always pass
``--payload-sha256``.

Other helper commands
~~~~~~~~~~~~~~~~~~~~~

The helper also serves ``keys vouch``, ``image build``, ``image verify``
and the operator ``bpm`` commands, and two commands that only scripts and
tooling call:

.. code-block:: none

   shirudo-build image sign-root <root-hash-file> -o <signature>
                 [--keys-dir <dir>] [--key <signing-key>] [--cert <certificate>]
   shirudo-build upatch rewrite-rodata <original> <modified> -o <output>
                 --data-range <offset>:<length> [--data-range ...]
                 [--keys-dir <dir>] [--key <signing-key>] [--cert <certificate>]

``image sign-root`` signs the 64 lowercase hexadecimal characters of a
dm-verity root hash. ``shirudo-gen-verity`` calls it. ``upatch
rewrite-rodata`` re-signs an artifact whose ``.rodata`` changed inside the
given ranges.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 18 25 35

   * - Option
     - Argument
     - Default
     - Description
   * - ``-o``
     - ``<output>``
     - see above
     - Where to write the artifact or directive.
   * - ``--name``
     - ``<name>``
     - input file name
     - Name of the upatch. Ignored with ``--unload``.
   * - ``--keys-dir``
     - ``<dir>``, next argument or after ``=``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - Directory holding ``signing_key.pem`` and ``cert.der``.
   * - ``--key``
     - ``<signing-key>``
     - from the keys directory
     - Private key, PEM, mode 0600. Overrides ``--keys-dir``.
   * - ``--cert``
     - ``<certificate>``
     - from the keys directory
     - Certificate, DER. Overrides ``--keys-dir``.
   * - ``--vmlinux``
     - ``<vmlinux-h>``
     - see above
     - ``vmlinux.h`` of the kernel the upatch is for.
   * - ``--extra-cflags``
     - ``<flags>``, one argument
     - none
     - Further clang flags. They come after the built-in ones, so a
       ``-mcpu`` among them replaces ``-mcpu=v4``.
   * - ``--emit-artifacts``
     - none
     - off
     - Keep the compiled object as ``<output without .upatch>.o`` and
       print the emitted paths on standard output.
   * - ``--attach-upatch``
     - ``<target-upatch>``
     - none
     - Attach the ``fentry``, ``fexit`` and ``freplace`` programs whose
       function is in the target's BTF to the programs of this upatch.
       The result loads only on top of exactly this build of the target.
       Only with ``--attach-object``. See
       :doc:`/upatches/write/attach-kinds`.
   * - ``--attach-object``
     - ``<target-object>``
     - none
     - The object the target upatch was built from, as
       ``--emit-artifacts`` keeps it. Only with ``--attach-upatch``.
   * - ``--unload``
     - ``<name>``
     - none
     - Sign an unload directive for the upatch ``<name>``.
   * - ``--payload-sha256``
     - ``<digest>``, 64 hex characters
     - see above
     - Payload digest the directive expects. Only with ``--unload``.
   * - ``-h``, ``--help``
     - none
     -
     - Print the helper's option list on standard output.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The artifact or directive was written.
   * - 1
     - The key or certificate is unusable, ``vmlinux.h`` or clang is
       missing, compilation failed, ``--attach-upatch`` came without
       ``--attach-object`` or the reverse, no program attaches to a
       program of the target upatch, or packaging and signing failed.
   * - 2
     - An unknown option, a second input, an input that is not
       ``.bpf.c``, ``.bpf.o`` or ``.o``, no input, an input together with
       ``--unload``, or a ``--payload-sha256`` that is not 64 hexadecimal
       characters.
   * - 127
     - ``shirudo`` cannot execute the helper.

Files and environment
---------------------

- Reads the key and certificate, ``vmlinux.h``, and for ``--unload``
  without a digest ``/var/lib/shirudo/upatches/<name>.upatch``
- Writes the output, and ``/tmp/shirudo-build-*.bpf.o`` while it compiles
- ``SHIRUDO_KEYS_DIR``: the default keys directory
- ``SHIRUDO_BUILD``: the helper ``shirudo`` executes

Examples
--------

Build and sign a upatch for the kernel whose ``vmlinux.h`` you name:

.. code-block:: console

   operator$ shirudo build basic.bpf.c --keys-dir <keys-dir> --vmlinux <vmlinux-h> -o basic.upatch
   wrote basic.upatch (insns=992 sig=4853 data=2456 sections=2 maps=0 progs=1 decoders=0 name=basic)

Sign the directive that unloads it, bound to its payload digest:

.. code-block:: console

   operator$ shirudo build --unload basic --payload-sha256 <payload-sha256> --keys-dir <keys-dir> -o basic.unload.upatch
   wrote basic.unload.upatch (insns=1320 sig=4853 data=2808 sections=2 maps=1 progs=1 decoders=0 name=basic UNLOAD)

``<keys-dir>`` holds the key pair, ``<vmlinux-h>`` is the target kernel's
``vmlinux.h`` and ``<payload-sha256>`` is the ``payload_sha256`` that
``shirudo upatch info --json basic.upatch`` prints.

Related
-------

- :doc:`upatch-info`
- :doc:`upatch-load`
- :doc:`upatch-unload`
- :doc:`/upatches/learn/kernel-fix-tutorial`
- :doc:`/reference/formats/upatch-format`
