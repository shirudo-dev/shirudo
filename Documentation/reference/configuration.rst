..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Configuration
=============

Every file shirudo takes settings from, every key, and the rules each
reader applies. ``shirudo config`` prints the settings in effect, see
:doc:`/reference/cli/config`.

Files
-----

Each authenticated file is vouched for by the one before it, from the
signed UKI on, as Figure 1 shows.

.. list-table::
   :header-rows: 1
   :widths: 26 34 40

   * - File
     - Location
     - Authenticated by
   * - Initrd bootstrap
     - ``/etc/shirudo/shirudo.conf`` inside the initrd
     - The UKI's Secure Boot signature, checked by the boot chain, not
       by shirudo
   * - Runtime bootstrap
     - ``etc/shirudo/shirudo.conf`` in the runtime image, read at
       ``/run/shirudo/runtime/etc/shirudo/shirudo.conf``
     - The runtime image's dm-verity root, pinned by
       ``runtime.root_hash`` in the initrd bootstrap
   * - Config settings
     - ``etc/shirudo/shirudo.conf`` in the config image, read through the
       image mounted at ``/run/shirudo/config``
     - The config image's signed dm-verity root
   * - Repository definitions, tree subscription, node labels, trusted
       and revoked keys
     - The config image, see `Config image`_
     - The config image's signed dm-verity root
   * - Host file
     - ``/etc/shirudo/shirudo.conf`` on the root file system
     - Nothing. Read on operator hosts. A target takes its settings from
       the bootstrap files and the config image.
   * - Unit environment files
     - ``/etc/shirudo/init.env``, ``/etc/shirudo/map-export.env``,
       ``/etc/shirudo/bpm/environment``
     - Nothing. See :doc:`/reference/environment`.

The two bootstrap files are different files with different required
keys. ``shirudo-gen-initrd --bootstrap-conf <file>`` embeds the initrd
bootstrap. ``shirudo-gen-runtime --bootstrap-conf <file>`` installs the
runtime bootstrap into the runtime image. See :doc:`/reference/cli/gen-tools`.

.. figure:: /images/reference-config-chain.svg
   :alt: The UKI, signed for Secure Boot, carries the initrd's bootstrap
         with runtime.image, runtime.root_hash and tpm settings. Its root
         hash pins the runtime image, whose runtime bootstrap holds
         config.image, config.verification_key, config.pcr and the tpm
         and tls settings, beside the config certificates.
         config.image selects the config image and the certificates
         verify its signed root; the config image holds eventlog and
         map_export settings, repositories, the upatch tree, node labels
         and keys. The host file and the unit environment files are not
         authenticated.

   Figure 1. Where a target's settings come from, and what authenticates
   each file.

Bootstrap keys
--------------

.. list-table::
   :header-rows: 1
   :widths: 24 22 14 14 26

   * - Key
     - Value
     - Initrd bootstrap
     - Runtime bootstrap
     - Meaning
   * - ``runtime.image``
     - Absolute path prefix
     - Required
     - Refused
     - Prefix of the runtime image files, see `Image files`_
   * - ``runtime.root_hash``
     - 64 hexadecimal digits
     - Required
     - Refused
     - Expected dm-verity root hash of the runtime image
   * - ``config.image``
     - Absolute path prefix under ``/var/lib/shirudo/images/``
     - Allowed
     - Required
     - Config image selected at boot while
       ``/var/lib/shirudo/config-update`` holds no activation record.
       Once a record exists, its prefix is selected instead.
   * - ``config.verification_key``
     - Absolute path under ``/run/shirudo/runtime/``
     - Allowed
     - Required
     - Repeatable, at most 16 DER certificates. Init enrolls them in
       ``.dm-verity``; the target also checks signatures against this
       exact set before mapping a config. ``shirudo-gen-runtime``
       installs the first as ``etc/shirudo/config-cert.der`` and further
       certificates as ``config-cert-2.der`` and on.
   * - ``config.pcr``
     - Decimal integer, 0 to 15, not 9 or 11
     - Allowed
     - Required, or ``config.nvpcr``
     - PCR that config activation extends
   * - ``config.nvpcr``
     - ``shirudo-config``
     - Allowed
     - Required, or ``config.pcr``
     - Extend the config NvPCR, NV index ``0x01818E04``, instead of a PCR
   * - ``enforcement.mode``
     - ``strict`` or ``shared``
     - Refused
     - Optional, ``strict`` when absent
     - How much of ``bpf()`` the guards keep from tasks without runtime
       authority, see :doc:`/internals/enforcement`. ``shared`` leaves
       other BPF users running beside shirudo on a host whose root is
       trusted.

The runtime bootstrap's ``config.*`` values are the ones in effect: the
root file system's run of ``init`` and every later command read only the
runtime bootstrap.

Bootstrap rules:

- A ``runtime.*`` key in the runtime bootstrap is refused with
  ``EINVAL``.
- An ``enforcement.*`` key in the initrd bootstrap is refused with
  ``EINVAL``, so the mode is part of the runtime image the initrd pins.
- A ``config.*``, ``runtime.*`` or ``enforcement.*`` key not in the table
  is refused with ``EINVAL``. A repeated ``runtime.image``,
  ``runtime.root_hash`` or ``enforcement.mode`` is refused with
  ``EINVAL``, as is a mode other than ``strict`` or ``shared``.
- A repeated ``config.verification_key`` adds another allowed certificate.
  A repeated path is refused with ``EEXIST`` and more than 16 entries
  with ``E2BIG``. Runtime loading also rejects duplicate public keys and
  certificates other than ML-DSA-87.
- A ``config.verification_key`` outside ``/run/shirudo/runtime/`` is
  refused with ``EPERM``.
- A path is valid when it is absolute and contains no ``//``, ``/./`` or
  ``/../``, does not end in ``/..`` and is not ``/``.
- A non-blank line that is not a comment and has no ``=`` is refused
  with ``EINVAL``. A line longer than 4223 bytes is refused with
  ``E2BIG``.
- Every other key in a bootstrap file is a setting, read as in
  `Settings`_.

``init`` reports a refused bootstrap file with ``init: authenticated
image settings: <error>`` or, for the runtime bootstrap in the initrd,
``image: load runtime config: <error>``, and exits with status 1.
Every other command fails with ``shirudo: image state: <error>`` and exit
status 1.

Settings
--------

.. list-table::
   :header-rows: 1
   :widths: 26 26 14 34

   * - Key
     - Value
     - Default
     - Set in
   * - ``eventlog.max_bytes``
     - Decimal integer, ``0`` for no limit
     - ``0``
     - Config image
   * - ``tpm.owner_auth``
     - Literal password, or ``hex:<even number of hex digits>``, at most
       256 bytes
     - Empty
     - Both bootstrap files
   * - ``tpm.tcti``
     - TCTI string, at most 255 bytes. ``device:<path>`` on a target
     - ``device:/dev/tpmrm0``
     - Both bootstrap files
   * - ``tls.classical_hosts``
     - Comma-separated exact DNS names, at most 1023 bytes
     - Empty
     - Runtime bootstrap on a target, host file on an operator host
   * - ``map_export.json_path``
     - Absolute path, or empty
     - Empty
     - Config image
   * - ``map_export.otel_endpoint``
     - ``http`` or ``https`` URL, at most 2047 bytes, or empty
     - Empty
     - Config image
   * - ``map_export.tenant_id``
     - 1 to 128 characters from ``A-Z``, ``a-z``, ``0-9``, ``.``,
       ``_``, ``-``, or empty
     - Empty
     - Config image
   * - ``map_export.otel_insecure``
     - ``true`` or ``false``
     - ``false``
     - Config image
   * - ``map_export.otel_retries``
     - Decimal integer, 0 to 10
     - ``3``
     - Config image
   * - ``map_export.s3_uri``
     - ``s3://<bucket>[/<prefix>]``, at most 2047 bytes, or empty
     - Empty
     - Config image
   * - ``map_export.log_record_max_bytes``
     - Decimal integer, 1 to 8388608
     - ``1048576``
     - Config image
   * - ``map_export.otlp_max_bytes``
     - Decimal integer, 1 to 8388608
     - ``4194304``
     - Config image

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Effect
   * - ``eventlog.max_bytes``
     - ``upatch load``, ``upatch unload`` and the register binding of
       ``init`` refuse with ``eventlog_full`` when the eventlog's size
       plus 4096 bytes exceeds this value.
   * - ``tpm.owner_auth``
     - Owner hierarchy authorization for defining the NV index. Needed
       only when the TPM's owner password is set. The initrd copy is
       read while ``init`` creates the NV writer and the attestation key
       in the initrd, the runtime copy for every later TPM use.
   * - ``tpm.tcti``
     - TPM connection for tpm2-tss. With a config image active, a value
       that does not begin with ``device:`` is refused with ``EACCES``.
       Read from the same two files as ``tpm.owner_auth``.
   * - ``tls.classical_hosts``
     - HTTPS hosts that may negotiate ``X25519`` or ``secp256r1`` key
       exchange in addition to the hybrid ML-KEM groups. Every other
       host is held to ``X25519MLKEM768`` and ``SecP256r1MLKEM768``.
       Each host, redirect targets included, must be listed by its exact
       name, compared without case. IP addresses cannot be listed. A
       classical handshake is logged as a warning.
   * - ``map_export.json_path``
     - ``upatch map --all`` appends each decoded map as one JSON line to
       this file.
   * - ``map_export.otel_endpoint``
     - OTLP/HTTP base URL. ``/v1/logs`` or ``/v1/metrics`` is appended.
       ``status --otel`` and ``upatch map --all`` send to it. Without it
       and without ``--otel``, ``upatch map --all`` sends no OTLP. Plain
       ``http`` is accepted for ``localhost``, ``127.0.0.1`` and
       ``[::1]`` only, unless ``map_export.otel_insecure`` is ``true``.
   * - ``map_export.tenant_id``
     - Sent as the ``X-Tenant-ID`` header.
   * - ``map_export.otel_insecure``
     - ``true`` allows ``http`` to any host and turns off certificate and
       host name verification for ``https``.
   * - ``map_export.otel_retries``
     - Further attempts after a failed OTLP or S3 request.
   * - ``map_export.s3_uri``
     - Object store for a snapshot larger than
       ``map_export.otlp_max_bytes``. The OTLP endpoint receives a
       reference event instead. Requires ``map_export.otel_endpoint``.
   * - ``map_export.log_record_max_bytes``
     - Largest OTLP log record. Must not exceed
       ``map_export.otlp_max_bytes``.
   * - ``map_export.otlp_max_bytes``
     - Largest OTLP request body.

On a target, the effective settings combine the files as follows:

- ``tpm.owner_auth``, ``tpm.tcti`` and ``tls.classical_hosts`` come from
  the bootstrap. The config image cannot carry them.
- ``eventlog.max_bytes`` and ``map_export.*`` come from the config image.
  A value in a bootstrap file applies only while no config image is
  active, as for ``status`` during an activation it cannot verify.
- On a host without a config image, ``SHIRUDO_TPM_TCTI`` and
  ``SHIRUDO_TPM_OWNER_AUTH`` override the file. A target refuses both,
  see :doc:`/reference/environment`.

See :doc:`/reference/formats/map-export` for what the ``map_export.*``
destinations receive.

Syntax and validation
---------------------

All three files and the host file share one syntax:

- One ``key = value`` per line. Blanks around the key and the value are
  removed.
- A line whose first non-blank character is ``#`` is a comment.
- A later line sets a key again, except the repeatable bootstrap
  ``config.verification_key``, which adds another certificate.
- A line without ``=`` is ignored, except in a bootstrap file and in the
  config image.

How each reader treats a bad value:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Value
     - Result
   * - Unknown key
     - Warning ``config: unknown key '<key>' (ignored)``.
   * - Unknown ``map_export.*`` key, or a ``map_export.*`` value out of
       range
     - Warning. Map export is invalid: ``status --otel`` and
       ``upatch map --all`` exit with status 2, ``shirudo config`` with
       status 1.
   * - Unknown ``tls.*`` key, or an invalid ``tls.classical_hosts``
     - Warning. No host may use classical key exchange. ``shirudo
       config`` exits with status 1.
   * - Invalid ``eventlog.max_bytes``, ``tpm.owner_auth`` or
       ``tpm.tcti``
     - Warning. The value is ignored.
   * - Line longer than 4223 bytes in the host file
     - Warning. The line is ignored.
   * - Line containing a NUL byte
     - The file is refused with ``EINVAL``.

The config image's ``etc/shirudo/shirudo.conf`` is checked again when an
image is validated, before its root is extended into the config PCR. The
image is refused when:

- the file is missing;
- a line is longer than 1023 bytes or contains a NUL byte (``E2BIG``);
- a non-blank line that is not a comment has no ``=`` (``EINVAL``);
- a key is neither ``eventlog.max_bytes`` nor ``map_export.*``
  (``EPERM``);
- ``eventlog.max_bytes`` is not a decimal integer (``EINVAL``);
- the map export settings are invalid (``EINVAL``).

.. _trusted-files:

Ownership and mode
~~~~~~~~~~~~~~~~~~

A settings, repository, tree or certificate file, and the registry auth
file and CA certificate that ``REGISTRY_AUTH_FILE`` and
``BPM_OCI_CA_FILE`` name, read from a path under ``/etc/shirudo`` or
``/var/lib/shirudo`` is refused with ``EPERM`` unless:

- it is a regular file owned by root or by the effective user;
- it is not writable by group or others;
- every directory the path leads through is owned by root or the
  effective user and is not writable by group or others, or is root's
  and sticky;
- every symbolic link on the path is owned by root or the effective
  user.

The path is resolved one name at a time, so the directory that holds a
symbolic link is checked as well as the directories of the link's
target. A link may lead out of ``/etc/shirudo``, to the distribution's
CA certificates for example, when every link and directory on the way
passes. A file that the path no longer names when the check runs, one
renamed over in between, is opened again and checked in full, up to
three more times. Only a name renamed over before every check is
refused, with ``ESTALE``. :doc:`/operate/troubleshoot/troubleshooting`
gives the messages.

A file that sets ``tpm.owner_auth`` must also not be readable by group or
others, mode ``0600`` or stricter. This applies to the initrd bootstrap
and the host file. Files read from the runtime and config images are
checked by their dm-verity roots instead. ``shirudo-gen-runtime``
installs the runtime bootstrap with mode ``0644``.

Config image
------------

A config image is a directory tree of regular files and directories on
one file system, at most 65536 entries and 32 levels deep. Symbolic
links, devices, FIFOs and sockets are refused with ``EPERM``.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Path in the image
     - Content
   * - ``etc/shirudo/shirudo.conf``
     - Required. ``eventlog.max_bytes`` and ``map_export.*`` only.
   * - ``etc/shirudo/bpm/registries.d/<name>.conf``
     - One repository definition each, see `Repository definition`_.
   * - ``etc/shirudo/bpm/keys/<file>``
     - Repository certificates named by ``key_file``.
   * - ``etc/shirudo/bpm/upatch-tree.conf``
     - The upatch tree subscription, see `Tree subscription`_.
   * - ``etc/shirudo/node.labels``
     - The labels tree selectors match, see `Node labels`_.
   * - ``keys/trusted/<name>.der``
     - Further BPF signing certificates. Each needs a
       ``keys/trusted/<name>.vouch`` from an already trusted key.
   * - ``keys/revoked/<fingerprint>.der``
     - A revoked certificate. ``<fingerprint>`` is the lowercase hex
       SHA-256 of its DER ``SubjectPublicKeyInfo``.

See :doc:`/operate/maintain/keys` for the trusted and revoked sets and
:doc:`/internals/config-images` for activation.

Runtime image
-------------

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Path in the image
     - Content
   * - ``usr/bin/shirudo``
     - The target binary (``--binary``).
   * - ``usr/bin/<name>``
     - Further executables (``--extra-binary``).
   * - ``etc/shirudo/shirudo.conf``
     - The runtime bootstrap (``--bootstrap-conf``).
   * - ``keys/cert.der``
     - The initial BPF signing certificate (``--cert``), always in the
       trusted set.
   * - ``etc/shirudo/config-cert.der``
     - The first config verification certificate (``--config-cert``).
   * - ``etc/shirudo/config-cert-2.der`` and on
     - Additional config verification certificates (repeat ``--config-cert``).
   * - The ELF interpreter and libraries
     - Copied at their own paths for a dynamic binary.

shirudo's part of the initrd
----------------------------

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Path in the initrd
     - Content
   * - ``/etc/shirudo/shirudo.conf``
     - The initrd bootstrap. The dracut module's install step fails
       when it cannot read the file.
   * - ``/etc/shirudo/keys/cert.der``
     - The primary certificate. The pre-flight check and the
       ``ConditionPathExists=`` of ``shirudo-initrd.service`` use it.
       The keys enrolled at boot come from the runtime and config images.
   * - ``/etc/shirudo/keys/trusted/*.der``, ``*.vouch``
     - Copied from ``trusted/`` beside the primary certificate.
   * - The shirudo binary
     - At its path on the root file system.

Image files
-----------

``runtime.image`` and ``config.image`` name a path prefix. The files are
the prefix with a suffix:

.. list-table::
   :header-rows: 1
   :widths: 20 20 20 40

   * - Suffix
     - Runtime image
     - Config image
     - Content
   * - ``.img``
     - Required
     - Required
     - ext4 file system
   * - ``.verity``
     - Required
     - Required
     - dm-verity superblock and hash tree
   * - ``.roothash``
     - Required
     - Required
     - Root hash as exactly 64 lowercase hex digits, no newline
   * - ``.p7s``
     - Not read
     - Required
     - Detached CMS signature over the 64 root hash bytes

Repository definition
---------------------

``etc/shirudo/bpm/registries.d/<name>.conf`` in the config image, or the
same path under ``/`` on a host without one. ``<name>`` is the
repository name: 1 to 127 characters from ``A-Z``, ``a-z``, ``0-9``,
``.``, ``_``, ``-``, not starting with ``.``.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Key
     - Value
   * - ``endpoint``
     - Required. ``oci://<host>[:<port>]``, no path, ``?``, ``#`` or
       ``@``.
   * - ``index_repository``
     - Optional. The OCI repository containing the signed index. When
       omitted, it defaults to ``<source>/bpm-index``; set ``<source>``
       to the package namespace to use the same namespace as the package
       repository. The repository must end in ``/bpm-index``.
   * - ``key_file``
     - Required. DER certificate that verifies the repository's signed
       index. With a config image, ``/etc/shirudo/bpm/keys/<file>``
       names the image's ``etc/shirudo/bpm/keys/<file>``, a relative path
       names a file under the image root, and any other absolute path or
       a path containing ``..`` is refused with ``EINVAL``.

Lines without ``=`` and other keys are ignored. Leading blanks of a value
are removed, trailing blanks are kept.

Tree subscription
-----------------

``etc/shirudo/bpm/upatch-tree.conf`` in the config image, or
``/etc/shirudo/bpm/upatch-tree.conf`` on a host without one. Without the
file, ``bpm tree sync`` does nothing.

.. list-table::
   :header-rows: 1
   :widths: 18 82

   * - Key
     - Value
   * - ``endpoint``
     - Required. ``oci://<host>[:<port>]/<repository>``. The repository
       may not contain ``..``, ``//`` or ``:``.
   * - ``reference``
     - Required. Tag or digest of the tree publication, without ``/``,
       ``?``, ``#`` or ``..``.

Either value may be enclosed in double quotes. An opening quote without
a closing one is refused with ``EINVAL``. Lines without ``=`` and other
keys are ignored. See :doc:`/reference/formats/upatch-tree` for the
publication.

Node labels
-----------

``etc/shirudo/node.labels`` in the config image, or
``/etc/shirudo/node.labels`` on a host without one.

- One ``key=value`` per line. Lines starting with ``#`` and lines
  without ``=`` are ignored.
- A line longer than 511 bytes, more than 64 labels, or a key or value
  longer than 255 bytes is an error for the tree operation being
  matched.
- Blanks after the ``=`` and at the end of the line are removed. Blanks
  between the key and the ``=`` are kept as part of the key, so write
  ``env=prod``, not ``env = prod``.
- Without the file, a tree operation whose selector names a label does
  not match.

Related
-------

- :doc:`/reference/environment` for the variables that override or
  complement these settings
- :doc:`/reference/files` for every path shirudo reads and writes
- :doc:`/operate/deploy/boot-integration` for building the bootstrap files and
  images
- :doc:`/operate/run/telemetry` for the export destinations
- :doc:`/operate/run/deliver-packages` for repositories and the upatch tree
