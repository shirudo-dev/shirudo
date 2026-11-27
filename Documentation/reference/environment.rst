..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Environment variables
=====================

Every environment variable that ``shirudo``, ``shirudo-build``, the
generator scripts and the libraries they link read. shirudo does not
clear or filter its environment beyond the refusals listed here.

Refused on a target
-------------------

``init``, and on a target that enforces every command except
``genkey``, ``build``, ``help``, ``version``, ``image build`` and
``image verify``, refuse to run when one of these variables is set, even
to an empty value. The command logs ``bootstrap override <name> is
forbidden`` and fails with ``EPERM`` and exit status 1.

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Variable
     - Effect on a host without a config image
   * - ``SHIRUDO_KEYS_DIR``
     - Key directory of ``genkey``, ``keys`` and ``shirudo-build``, in
       place of ``/var/lib/shirudo/keys``. A ``--keys-dir`` option takes
       precedence.
   * - ``SHIRUDO_TPM_TCTI``
     - TCTI in place of ``tpm.tcti``.
   * - ``SHIRUDO_TPM_OWNER_AUTH``
     - TPM owner password in place of ``tpm.owner_auth``, as a literal
       or ``hex:<even number of hex digits>``.
   * - ``SHIRUDO_EVENTLOG_PATH``
     - Eventlog path in place of ``/var/lib/shirudo/eventlog``. The
       register lock is then a file beside it, ``<path>.lock``, in place
       of the root of the private bpffs.
   * - ``SHIRUDO_EVENTLOG_PENDING_PATH``
     - Pending eventlog record in place of
       ``/run/shirudo/eventlog.pending``.
   * - ``SHIRUDO_INITRD_RELEASE``
     - File whose existence means "running in the initrd", in place of
       ``/etc/initrd-release``.
   * - ``SHIRUDO_SYSROOT``
     - Root file system mount point in the initrd, in place of
       ``/sysroot``.

``SHIRUDO_KEYS_DIR`` also serves operator hosts. The others serve
development and tests.

``TSS2_LOGFILE`` and ``SSLKEYLOGFILE`` are refused on a target the same
way. tpm2-tss and libcurl open the file they name with the process's
authority, sealed state included, and neither has a use on a target.

shirudo and shirudo-build
-------------------------

.. list-table::
   :header-rows: 1
   :widths: 24 30 46

   * - Variable
     - Read by
     - Effect
   * - ``SHIRUDO_BUILD``
     - ``shirudo`` when it hands an operator command to the helper;
       ``shirudo-gen-image``, ``shirudo-gen-runtime``,
       ``shirudo-gen-verity``
     - Path of ``shirudo-build``. Unset, ``shirudo`` uses
       ``$(libexecdir)/shirudo/shirudo-build`` and then
       ``shirudo-build`` on ``PATH``, and the scripts use
       ``shirudo-build`` on ``PATH``. ``shirudo`` fails with exit status
       127 when the value is empty.
   * - ``PATH``
     - ``shirudo`` looking up ``shirudo-build``; ``shirudo-build``
       running ``veritysetup``; the generator scripts
     - Search path. ``shirudo-build`` runs ``clang`` only from the path
       fixed when it was built: ``/usr/bin/clang``, or
       ``/usr/lib/llvm-23/bin/clang`` in the Debian package.
   * - ``SHIRUDO_INIT_ARGS``
     - ``shirudo.service``, from ``/etc/shirudo/init.env``
     - Arguments appended to ``init``. ``init`` accepts only
       ``--check-only`` and ``--json``. The runtime drop-in clears
       ``ExecStart=`` and ``EnvironmentFile=``, so the variable has no
       effect with it.
   * - ``JOURNAL_STREAM``
     - ``shirudo`` and ``shirudo-build``, for their messages
     - Set by systemd to the device and inode of the journal stream a
       service's output is connected to. When it names the file that is
       standard error, and ``/dev/log`` exists, messages go to syslog
       alone, so that the journal holds each once. Honored on a target.
   * - ``TMPDIR``
     - ``shirudo-build bpm build`` (staging directory), the generator
       scripts (``mktemp -d``)
     - Directory for temporary files, ``/tmp`` when unset or empty.
   * - ``HOME``
     - Registry credential lookup; ``shirudo-build bpm build`` expanding
       ``~`` in its key directory
     - ``$HOME/.docker/config.json`` holds registry credentials.
       ``/root`` when unset.

Registry access
---------------

Read by the target's ``bpm`` commands and by ``shirudo-build bpm push``,
``shirudo-build bpm tree append`` and ``shirudo-build bpm tree show``.
Honored on a target.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Variable
     - Effect
   * - ``BPM_OCI_SCHEME``
     - ``https`` (default) or ``http``. ``http`` sends registry traffic
       without TLS. Any other value fails with ``bpm OCI: BPM_OCI_SCHEME
       must be https or http``.
   * - ``BPM_OCI_CA_FILE``
     - PEM file whose first certificate is added to the trusted CAs of
       registry connections. Under ``/etc/shirudo`` or
       ``/var/lib/shirudo``, the file and each directory and symbolic
       link on its path must pass :ref:`trusted-files`.
   * - ``BPM_OCI_USERNAME``, ``BPM_OCI_PASSWORD``
     - Registry credentials. Used only when both are set, ahead of any
       auth file.
   * - ``BPM_OCI_BEARER_TOKEN``
     - Bearer token sent when a registry asks for one, in place of a
       token from the registry's token service.
   * - ``REGISTRY_AUTH_FILE``
     - Auth file in ``config.json`` form, read when the two variables
       above are not both set.
   * - ``DOCKER_CONFIG``
     - Directory holding ``config.json``, read when
       ``REGISTRY_AUTH_FILE`` is unset. Without either,
       ``$HOME/.docker/config.json`` is read. An auth file that holds a
       NUL byte is refused, wherever it is read from. Under
       ``/etc/shirudo`` or ``/var/lib/shirudo``, an auth file and each
       directory and symbolic link on its path must pass
       :ref:`trusted-files`.

Telemetry export
----------------

Read by ``status --otel`` and by ``upatch map --otel`` and ``--all``.
Honored on a target. ``<SIGNAL>`` is ``LOGS`` or ``METRICS``. A
per-signal variable takes precedence over the generic one. See
:doc:`/reference/formats/otlp`.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Variable
     - Effect
   * - ``OTEL_EXPORTER_OTLP_ENDPOINT``
     - Base URL, ``/v1/logs`` or ``/v1/metrics`` appended. Used when
       neither ``map_export.otel_endpoint``, ``--otel-endpoint`` nor the
       per-signal variable is set. Default ``http://localhost:4318``,
       except that ``status --otel`` sends nothing without a configured
       endpoint.
   * - ``OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT``
     - Full URL, used as given.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]PROTOCOL``
     - Must be ``http/json``.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]COMPRESSION``
     - ``none`` or ``gzip``.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]HEADERS``
     - Comma-separated ``name=value`` pairs, values percent-decoded.
       ``Content-Type``, ``Content-Encoding``, ``Content-Length``,
       ``Host`` and ``User-Agent`` are refused. An ``X-Tenant-ID`` pair
       yields to ``map_export.tenant_id`` and ``--tenant-id``.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]CERTIFICATE``
     - CA file for the collector's certificate.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]CLIENT_CERTIFICATE``,
       ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]CLIENT_KEY``
     - Client certificate and key, both or neither.
   * - ``OTEL_EXPORTER_OTLP_[<SIGNAL>_]TIMEOUT``
     - Request timeout in milliseconds, 1 to 120000. Default 10000.
   * - ``AWS_REGION``, ``AWS_DEFAULT_REGION``
     - Region of ``map_export.s3_uri``, in this order. Default
       ``us-east-1``.
   * - ``AWS_ENDPOINT_URL_S3``
     - S3 endpoint in place of the region's.
   * - ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``
     - S3 credentials. Required for an S3 upload.
   * - ``AWS_SESSION_TOKEN``
     - S3 session token.
   * - ``AWS_CA_BUNDLE``
     - CA file for the S3 endpoint.

Libraries
---------

These variables control library behavior. Target entry refuses the log
file destinations described above, and TPM setup always disables library
logging, including during bootstrap.

.. list-table::
   :header-rows: 1
   :widths: 26 16 58

   * - Variable
     - Library
     - Effect
   * - ``SSLKEYLOGFILE``
     - libcurl
     - libcurl appends the TLS session secrets of every registry, OTLP
       and S3 connection to this file. The static target's libcurl is
       built with this support. Anyone who reads the file can decrypt
       the captured traffic.
   * - ``http_proxy``, ``https_proxy``, ``HTTPS_PROXY``, ``all_proxy``,
       ``ALL_PROXY``, ``no_proxy``, ``NO_PROXY``
     - libcurl
     - Proxy for registry, OTLP and S3 connections. ``HTTP_PROXY`` in
       upper case is not read.
   * - ``TSS2_LOG``
     - tpm2-tss
     - Log levels of the TPM library. shirudo always forces ``all+none``,
       including during bootstrap, because library debug logs can expose
       session secrets.
   * - ``TSS2_LOGFILE``
     - tpm2-tss
     - Destination of those logs: ``stderr`` (default), ``stdout`` or
       ``-``, or a file opened for appending. Refused on a target.
       TPM connection setup always clears it before library initialization.
   * - ``LIBBPF_LOG_LEVEL``
     - libbpf
     - ``warn``, ``info`` (default) or ``debug`` for libbpf's messages
       on standard error.
   * - ``LIBBPF_BPF_TOKEN_PATH``
     - libbpf
     - bpffs path from which libbpf creates a BPF token when ``init``
       loads its own BPF objects. Set to a non-empty value, a failure to
       create the token fails the load.
   * - ``OPENSSL_CONF``
     - OpenSSL
     - Not read. shirudo initializes OpenSSL without its configuration
       file.

Generator and installer scripts
-------------------------------

.. list-table::
   :header-rows: 1
   :widths: 26 30 44

   * - Variable
     - Read by
     - Effect
   * - ``SHIRUDO_KEYS_DIR``
     - ``shirudo-gen-verity``
     - Key directory when ``--keys-dir`` is not given. Default
       ``/var/lib/shirudo/keys``.
   * - ``SHIRUDO_REPO``
     - :src:`tools/gen-initrd/install.sh`
     - GitHub repository releases are fetched from. Default
       ``shirudo-dev/shirudo``.
   * - ``SHIRUDO_CERT``
     - :src:`tools/gen-initrd/install.sh`
     - Same as ``--cert``.
   * - ``SHIRUDO_CERT_SHA256``
     - :src:`tools/gen-initrd/install.sh`
     - Same as ``--cert-sha256``.
   * - ``SHIRUDO_VERSION``
     - :src:`tools/gen-initrd/install.sh`
     - Same as ``--version``.
   * - ``SHIRUDO_PACKAGE``
     - :src:`tools/gen-initrd/install.sh`
     - Same as ``--package``.
   * - ``DESTDIR``
     - ``install.sh`` of the target tarball
     - Installation root. Default ``/``.

Environment files
-----------------

The units read these files with ``EnvironmentFile=-<file>``. A missing
file is not an error. They are host files on the root file system,
outside the sealed state under ``/var/lib/shirudo`` and outside the
signed config. Root can change them, and the next run of the unit uses
what they hold. See :doc:`/operate/plan/hardening`.

.. list-table::
   :header-rows: 1
   :widths: 32 34 34

   * - File
     - Units
     - Typical variables
   * - ``/etc/shirudo/init.env``
     - ``shirudo.service``, unless the runtime drop-in clears it
     - ``SHIRUDO_INIT_ARGS``
   * - ``/etc/shirudo/map-export.env``
     - ``shirudo-keepalive.service``, ``shirudo-map-export.service``
     - ``OTEL_EXPORTER_OTLP_*``, ``AWS_*``
   * - ``/etc/shirudo/bpm/environment``
     - ``shirudo-bpm-repo-update.service``,
       ``shirudo-bpm-tree-sync.service``
     - ``BPM_OCI_*``, ``REGISTRY_AUTH_FILE``, ``DOCKER_CONFIG``, proxy
       variables

A variable from the first table set in one of these files makes the
unit's command fail on a target.

Related
-------

- :doc:`/reference/systemd-units` for the units that read the
  environment files
- :doc:`/reference/configuration` for the settings these
  variables complement
- :doc:`/operate/run/telemetry` and :doc:`/operate/run/deliver-packages` for
  setting up export and registry access
