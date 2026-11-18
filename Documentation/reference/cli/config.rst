..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo config
==============

Print the effective shirudo configuration in ``shirudo.conf`` syntax.

Runs on: any host, and on a target as root with the runtime binary. Requires:
nothing. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo config

Description
-----------

``config`` loads the configuration the other commands use and prints
every setting with a comment above it. The first line names the source:

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - First line
     - Source
   * - ``# shirudo config (authenticated config image; TPM settings from runtime image)``
     - The active signed config image. ``tpm.*`` come from the runtime
       image.
   * - ``# shirudo config (effective, loaded from /etc/shirudo/shirudo.conf)``
     - ``/etc/shirudo/shirudo.conf`` on a host without an active config
       image.
   * - ``# shirudo config (no /etc/shirudo/shirudo.conf present; defaults shown)``
     - Built-in defaults.

Without an active config image, ``SHIRUDO_TPM_OWNER_AUTH`` and
``SHIRUDO_TPM_TCTI`` override the file, and the line of each overridden
setting names the variable. ``tpm.owner_auth`` is never printed. The
output gives its length and source instead.

The output is a starting point for a new file on a host without config
images:

.. code-block:: console

   # shirudo config > /etc/shirudo/shirudo.conf

The comments in the output are not a reference. The ``map_export``
comment is wrong: it says that empty destinations leave the export timer
idle, while the timer runs ``upatch map --all``, which reads every map
and prints it (see :doc:`upatch-map`).
:doc:`/reference/configuration` describes every setting.

Options
-------

``config`` takes no option except ``--help``.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - The configuration was printed and is valid.
   * - 1
     - ``/etc/shirudo/shirudo.conf`` exists and cannot be loaded, or the
       printed ``map_export`` or ``tls.classical_hosts`` settings are
       invalid. In the second case the configuration is still printed.
   * - 2
     - An option or an argument: ``config`` takes none.

Files and environment
---------------------

- ``/etc/shirudo/shirudo.conf``
- ``/run/shirudo/config``: the active config image
- ``SHIRUDO_TPM_OWNER_AUTH``, ``SHIRUDO_TPM_TCTI``: honored only
  without an active config image. The image gate refuses both on an
  enforcing target

Examples
--------

Print the configuration of a target with an active config image:

.. code-block:: console

   target# shirudo config

The command prints:

.. code-block:: none

   # shirudo config (authenticated config image; TPM settings from runtime image)

   # Eventlog cap; 0 = unlimited. When the log would exceed this,
   # the state-changing op refuses with category: eventlog_full.
   eventlog.max_bytes = 0

   # TPM owner-hierarchy password used at NV-index define time.
   # Empty by default (works on fresh TPMs, swtpm, most cloud VMs);
   # set on TPMs whose owner auth was already provisioned by
   # another tool. Literal string, or `hex:<even hex>` for a
   # binary auth value. May also be supplied via the
   # SHIRUDO_TPM_OWNER_AUTH env var; that override wins.
   # tpm.owner_auth = (unset)

   # TCTI override for the TPM library connection. Empty (default)
   # means the kernel resource manager at `device:/dev/tpmrm0`.
   # Set to `swtpm:host=<addr>,port=<port>` for a software TPM
   # emulator (dev/CI without real hardware); testing/swtpm.sh
   # in the source tree starts one. Pre-flight skips the
   # /dev/tpmrm0 check when this is set. The SHIRUDO_TPM_TCTI
   # env var overrides this in turn.
   tpm.tcti = device:/dev/tpmrm0  # from runtime image

   # Exact DNS hosts that may use classical TLS key exchange.
   # Targets honor this only from the immutable runtime image;
   # operators use the root-managed /etc/shirudo/shirudo.conf.
   # Leave empty for hybrid-only TLS.
   tls.classical_hosts =

   # Periodic `shirudo upatch map --all` export. Empty JSON and
   # OTLP destinations leave the installed timer idle. Every emitted
   # map must carry a signed Lua decoder declaring log or metric.
   # OTEL headers, TLS material, and AWS credentials belong in
   # /etc/shirudo/map-export.env for the systemd service.
   map_export.json_path =
   map_export.otel_endpoint =
   map_export.tenant_id = config-boot-keys
   map_export.otel_insecure = false
   map_export.otel_retries = 3
   map_export.s3_uri =
   map_export.log_record_max_bytes = 1048576
   map_export.otlp_max_bytes = 4194304

Related
-------

- :doc:`/reference/configuration`
- :doc:`/internals/config-images`
- :doc:`image`
