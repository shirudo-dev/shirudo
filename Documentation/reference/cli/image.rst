..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo image
=============

Build and verify signed dm-verity images on the operator host, and
activate a signed config image on a target, or select one for its next boot.

Runs on: ``build`` and ``verify`` on the operator host, through the
``shirudo-build`` helper, without the image gate. ``update``, ``stage`` and
``status`` on a target, as root with the runtime binary. Requires: ``veritysetup`` on the
operator host. Changes measured state: ``update`` yes, the others no.

Usage
-----

.. code-block:: none

   shirudo image build <filesystem-image> (--output | -o) <prefix>
                       [--kind config|runtime] [--keys-dir <dir>]
                       [--key <signing-key>] [--cert <certificate>]
                       [--salt <salt>]
   shirudo image verify <prefix> --cert <certificate>
   shirudo image update <prefix>
   shirudo image stage <prefix>
   shirudo image stage --cancel
   shirudo image status [--json]
   shirudo image --list-cmds

The subcommand names must be spelled out. ``image`` without a subcommand
prints the usage and exits with 2. ``--list-cmds`` prints
``build``, ``verify``, ``update``, ``stage`` and ``status``, one a line.

An image is four files that share a prefix: ``<prefix>.img`` (the ext4
file system), ``<prefix>.verity`` (the hash tree), ``<prefix>.roothash``
(64 lowercase hexadecimal characters) and ``<prefix>.p7s`` (the
ML-DSA-87 signature over those 64 characters).

image build
-----------

The helper runs ``shirudo-gen-verity`` (see :doc:`gen-tools`) with the
arguments, which:

#. checks that the input is a regular file, not a symbolic link,
   non-empty, a multiple of 4096 bytes and at most 1 TiB, and that none of
   the four output files exists,
#. copies the input and runs ``veritysetup format`` with SHA-256, 4096-byte
   blocks and, with ``--salt``, the given salt,
#. signs the root hash with ``shirudo-build image sign-root``, verifies
   the result with ``shirudo-build image verify``, and links the four
   files into place,
#. prints the root hash.

Every option takes its value as the next argument. ``--kind`` must be
``config`` or ``runtime`` and changes nothing else. ``image build
--help`` prints the usage of ``shirudo-gen-verity``. To build the file
system from a directory, use ``shirudo-gen-image`` or
``shirudo-gen-runtime`` (:doc:`gen-tools`).

image verify
------------

The helper reads ``<prefix>.roothash`` and ``<prefix>.p7s``, checks that
``--cert`` is an ML-DSA-87 certificate that signed the root hash, runs
``veritysetup verify`` on the data and hash files it opened, and prints the
root hash. The arguments must come in exactly this order:
``verify <prefix> --cert <certificate>``.

image update
------------

``update`` activates a new signed config image on a target. ``<prefix>``
is a local path prefix or an ``https://`` URL prefix.

#. It fetches ``<prefix>.roothash``, ``.p7s``, ``.img`` and ``.verity``
   into a staging directory under ``/var/lib/shirudo/images``, over HTTPS
   with redirects to HTTPS only, or from local regular files.
#. It verifies the root signature against the config certificates in
   the authenticated runtime image. It also checks the signature through
   the kernel's dm-verity trust path, maps the image read-only and reads
   it completely.
#. It links the files to ``/var/lib/shirudo/images/<root-hash>.*``. When
   the root hash is the active one, it stops here.
#. It maps and mounts the candidate, validates its settings, and checks
   that every signer its trusted set names is already in the ``.bpf``
   keyring. A live update cannot enroll a new key.
#. It records the activation as pending, extends the config PCR named in
   the bootstrap settings with an ``UPDATE`` event, checks the PCR value
   and appends the event to the activation records.
#. It applies the revocations in the image: each revoked certificate
   leaves the ``.bpf`` keyring, the register receives a ``key_revoke``
   event, and every archived upatch the certificate signed is unloaded
   and measured. It mounts the image at ``/run/shirudo/config``.
#. It clears the pending record and any previous next-boot selection.
   Updating to the already active root is a no-op and preserves that
   selection.

When libcurl supports asynchronous DNS and quick cleanup, Ctrl-C during
an HTTPS transfer removes the staged downloads and then ends the command
by SIGINT, so that a script running it stops as well.

When ``update`` stops between steps 5 and 7, the activation stays pending.
Every command except ``status`` and ``image status`` is then refused
until the next reboot.
shirudo does not reboot the target.

image stage
-----------

``stage <prefix>`` fetches and verifies a config in the same way as
``update``, but saves it for the next planned reboot instead of activating
it. It checks the settings and BPF certificate vouches. It permits a
vouched signer that the current sealed ``.bpf`` keyring does not yet hold.

The current config must be consistent. The staged selection is stored
in ``/var/lib/shirudo/config-update/next-boot`` and tied to the current
activation sequence and TPM boot. Staging does not change the mounted
config, either keyring, the config PCR or the measurement register.

At the next TPM boot, init verifies that the parent selection is
unchanged, rechecks the candidate and its signature, and enrolls its BPF
signers before sealing ``.bpf``. It measures the selected config through
the normal boot path. The next-boot record is removed only after init
completes. A re-run of init in the current boot cannot activate it.

``stage --cancel`` removes the next-boot selection without changing the
active config. Staging again replaces it. Activating a different config
root through a live update invalidates it. An interruption before the atomic selection is saved
leaves the previous selection in place. A saved selection whose files
cannot be authenticated causes init to refuse it.

.. list-table:: ``image update`` and ``image stage`` compared
   :header-rows: 1
   :widths: 24 38 38

   * - Property
     - ``image update``
     - ``image stage``
   * - Takes effect
     - At once.
     - At the next TPM boot, when init has verified it again.
   * - New BPF signers
     - Refused: every signer must already be in ``.bpf``.
     - Allowed when vouched; init enrolls them before it seals ``.bpf``.
   * - Revocations
     - Applied at once, each measured, with the archived upatches the
       revoked certificate signed unloaded.
     - Applied by init at the next boot.
   * - Changes now
     - The mounted config, ``.bpf``, the config PCR and the
       measurement register.
     - Only ``/var/lib/shirudo/config-update/next-boot``.
   * - After an interruption
     - Between steps 5 and 7, the activation stays pending and commands
       are refused until the next reboot.
     - Before the selection is saved, the previous selection stays.
   * - Undone by
     - Another ``image update``.
     - ``image stage --cancel``, or a live update to another root.

image status
------------

``status`` prints the active selection: the config root hash, the config
PCR, the sequence number, the TPM reset count, the restart count, whether
the activation is pending (``no``, or ``yes, until the next reboot``) and
whether it is consistent with its records (``yes`` or ``no``). With
``--json`` it prints one JSON object with ``root_hash``, ``pcr``,
``sequence``, ``reset_count``, ``restart_count``, ``pending`` and
``consistent`` instead. The text report also prints the next-boot config
root, or ``none``. JSON adds ``next_boot_root_hash``, a string or ``null``.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 16 22 30 32

   * - Option
     - Argument
     - Default
     - Description
   * - ``-o``, ``--output``
     - ``<prefix>``
     - none, required
     - ``build``: the output prefix.
   * - ``--kind``
     - ``config`` or ``runtime``
     - ``config``
     - ``build``: validated, no other effect.
   * - ``--keys-dir``
     - ``<dir>``
     - ``$SHIRUDO_KEYS_DIR``, else ``/var/lib/shirudo/keys``
     - ``build``: directory of the signing key and certificate.
   * - ``--key``
     - ``<signing-key>``
     - ``<dir>/signing_key.pem``
     - ``build``: the signing key.
   * - ``--cert``
     - ``<certificate>``
     - ``<dir>/cert.der`` for ``build``, required for ``verify``
     - ``build``: the signing certificate. ``verify``: the certificate
       to verify against.
   * - ``--salt``
     - ``<salt>``, 64 hex characters
     - chosen by ``veritysetup``
     - ``build``: the dm-verity salt.
   * - ``--cancel``
     - none
     - off
     - ``stage``: cancel the next-boot selection.
   * - ``--json``
     - none
     - off
     - ``status``: print the JSON object.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Success. ``status``: the activation is complete and consistent.
   * - 1
     - ``build``: a failure or a usage error reported by
       ``shirudo-gen-verity``. ``verify``: the signature or the hash tree
       does not verify, or a file is missing. ``update``: refused or
       failed, and while pending ``image: activation is pending; further
       changes are blocked``. ``status``: the activation is pending or
       inconsistent, and the report is still printed. On a host without
       config activation state, ``update`` fails with ``image update: No
       such device`` and ``status`` with ``image status: no config
       activation state on this host``.
   * - 2
     - No subcommand, an unknown subcommand, an unknown option or one
       given twice, a wrong number of arguments to ``update``, ``stage``
       or ``status``, ``stage`` with both a prefix and ``--cancel`` or
       neither, or ``verify`` without a prefix or ``--cert``.
   * - 127
     - ``build``, ``verify``: ``shirudo`` cannot execute the helper.

``shirudo-gen-verity`` stops at the first failing tool, so ``build`` can
also exit with that tool's status, for example ``veritysetup``'s.

Files and environment
---------------------

- ``build``: the four output files and a temporary directory beside
  them. ``SHIRUDO_KEYS_DIR`` and ``SHIRUDO_BUILD`` set the defaults of
  ``shirudo-gen-verity``
- ``update``: ``/var/lib/shirudo/images``, ``/var/lib/shirudo/config-update``,
  ``/run/shirudo/config``, the config PCR and the register
- ``stage``: the image cache and ``config-update/next-boot``; it leaves
  the active config and measurements unchanged

Examples
--------

Sign an ext4 image as a config image:

.. code-block:: console

   operator$ shirudo image build config.ext4 --output config --keys-dir ~/shirudo-keys

Verify an image offline:

.. code-block:: console

   operator$ shirudo image verify config --cert config-cert.der

Activate a config image a web server publishes:

.. code-block:: console

   target# shirudo image update https://config.example/shirudo/config

Show the active selection:

.. code-block:: console

   target# shirudo image status
   Config root hash:      6d5ed552f4487728d1ccec8604ddb44b66b18e3430614c20bb4d284995f99f63
   Next boot root hash:   none
   PCR:                   14
   Sequence:              1
   TPM reset count:       1
   Restart count:         0
   Pending:               no
   Consistent:            yes

Related
-------

- :doc:`/internals/config-images`
- :doc:`/concepts/background/dm-verity`
- :doc:`gen-tools`
- :doc:`/reference/configuration`
- :doc:`/operate/maintain/keys`
