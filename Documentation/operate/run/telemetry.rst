..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Monitor and export telemetry
============================

A target pushes two kinds of telemetry to a collector: a status
keepalive and snapshots of the maps its upatches keep. Both leave as
OTLP/HTTP requests with JSON bodies, sent by one-shot commands that
systemd timers start. Nothing connects to the target. This page shows
how to choose the destination, set up the collector, check the pipeline
and decide what to alert on.

Telemetry is the target's own account of itself, so it tells you where
to look, not what is true. The keepalive carries a quote by the target's
TPM attestation key, which shows that its body is unchanged since that
key signed it, but not that the key lives in a genuine TPM. Map
snapshots carry no proof of origin at all. Evidence that a target cannot
forge comes from the TPM, through :doc:`/operate/run/attest`.

What a target sends
-------------------

.. list-table::
   :header-rows: 1
   :widths: 26 30 44

   * - Timer
     - Runs
     - Sends
   * - ``shirudo-keepalive.timer``
     - ``shirudo status --otel``
     - One log record, ``shirudo.keepalive``: the keepalive body and its
       TPM quote, when an OTLP endpoint is configured. Nothing otherwise.
   * - ``shirudo-map-export.timer``
     - ``shirudo upatch map --all``
     - One record per pinned map to every destination the config names:
       JSON lines, OTLP, or both. With no destination, the dump goes to
       the journal.

Both timers start their service 5 seconds after boot. The keepalive
timer starts it again 60 seconds after each run ends, the map-export
timer 5 seconds after. ``shirudo-map-export.service`` runs only while
``/run/shirudo/bpffs/lsm_link`` exists.

A keepalive and a ``bpm tree sync`` stall each other rather than run at
once. Every target command holds the config operation lock for its whole
run, and a sync holds it until its last operation is applied. A
keepalive that starts during a sync waits up to 30 seconds for the lock;
when the sync is still running then, that run fails and sends nothing,
and the next run of the timer tries again. A sync that fetches and
applies for minutes therefore leaves a gap of about that length in the
node's keepalives, which a backend's threshold for a stale node must
allow for. See :doc:`/reference/systemd-units`.

The keepalive record has the event name ``shirudo.keepalive``. Its body
is a string, the keepalive body that ``shirudo status --keepalive``
prints: one compact JSON object of about a kilobyte with the verdict,
the conditions, the tamper and integrity counters, the build, the
config and image,
the tree the target follows and the upatches it has loaded
(:doc:`/reference/cli/status`). Its one attribute, ``shirudo.quote``, is
the TPM quote of the SHA-256 of the body by the attestation key of
``shirudo attest``. A target whose TPM does not answer sends no
keepalive. Its severity follows the verdict:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Severity
     - Verdict
   * - ``INFO`` (9)
     - ``ok``
   * - ``WARN`` (13)
     - ``degraded``, ``init-pending``, ``reboot-pending``
   * - ``ERROR`` (17)
     - Every other verdict, ``tampered`` and ``lsm-off`` among them

A map snapshot has the event name ``shirudo.bpf.map.snapshot``. Its body
is what the map's signed decoder returns, or the map's entries when the
upatch ships no decoder for it. A decoder can return metrics instead of
a log record. Every request carries the resource attributes
``service.name`` (``shirudo``), ``service.version`` and ``host.name``.
:doc:`/reference/formats/otlp` describes every field.

Before you begin
----------------

- On the target, ``shirudo`` stands for the runtime image's binary,
  ``/run/shirudo/runtime/usr/bin/shirudo`` (:ref:`runtime-invocation`).
- The keepalive and map-export services invoke that binary directly on
  static target packages; for a dynamically linked binary, install the
  drop-ins from ``shirudo-gen-runtime --unit-dir`` (:ref:`unit-drop-ins`).
- A collector that accepts OTLP over HTTP with JSON bodies, reachable
  from the target over TLS 1.3.
- On the operator host, the source directory of the target's config
  image and the key that signs config images.

Set the destination
-------------------

The destination belongs in the signed config image, in
``etc/shirudo/shirudo.conf``. The target ignores the host's
``/etc/shirudo/shirudo.conf`` while a config image is active.

#. In the config source directory, add the export settings to
   ``etc/shirudo/shirudo.conf``:

   .. code-block:: text

      map_export.otel_endpoint = https://<collector-host>:4318
      map_export.tenant_id = <tenant>

   ``<collector-host>`` is the collector's DNS name. ``<tenant>`` is an
   optional label that the target sends as the ``X-Tenant-ID`` header.

#. Build, sign and activate the config, as described in
   :ref:`deliver-packages-config-update`.

#. Check the effective settings on the target:

   .. code-block:: console

      target# shirudo config
      # shirudo config (authenticated config image; TPM settings from runtime image)
      ...
      map_export.json_path =
      map_export.otel_endpoint =
      map_export.tenant_id = config-boot-keys
      map_export.otel_insecure = false
      map_export.otel_retries = 3
      map_export.s3_uri =
      map_export.log_record_max_bytes = 1048576
      map_export.otlp_max_bytes = 4194304

   The first line says that the settings come from the authenticated
   config image. This target's config names no destination yet, so
   ``map_export.otel_endpoint`` is empty. After your update it shows
   your collector.

The config image accepts these keys:

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Key
     - Meaning
   * - ``map_export.otel_endpoint``
     - Base URL of the collector. The target appends ``/v1/logs`` or
       ``/v1/metrics``. ``http://`` is allowed only to ``localhost``,
       ``127.0.0.1`` and ``[::1]``, and a URL with a user name or
       password is refused. Default: empty.
   * - ``map_export.tenant_id``
     - Value of the ``X-Tenant-ID`` header, 1 to 128 characters from
       ``A-Z``, ``a-z``, ``0-9``, ``.``, ``_`` and ``-``. Default: empty,
       no header.
   * - ``map_export.otel_insecure``
     - ``true`` allows ``http://`` to any host and turns off certificate
       and host name checks for ``https://``. The command prints a
       warning each time. Default: ``false``.
   * - ``map_export.otel_retries``
     - Retries after a failed request, 0 to 10. Default: 3.
   * - ``map_export.json_path``
     - Absolute path of a file to which ``upatch map --all`` appends
       one JSON line per map. Default: empty.
   * - ``map_export.s3_uri``
     - S3 location for a decoded snapshot too large for one OTLP
       record. The collector then receives a record that points to the
       object. Requires ``map_export.otel_endpoint``. Default: empty.
   * - ``map_export.log_record_max_bytes``
     - Largest log record, 1 to 8388608 bytes, at most
       ``map_export.otlp_max_bytes``. Default: 1048576.
   * - ``map_export.otlp_max_bytes``
     - Largest request body before compression, 1 to 8388608 bytes.
       Default: 4194304.

The only other key the config image's ``shirudo.conf`` accepts is
``eventlog.max_bytes``. :doc:`/reference/configuration` lists
every key, including those of the runtime image.

Set credentials and TLS material
--------------------------------

Credentials, headers and certificates are environment variables, not
configuration. systemd reads them for both services from
``/etc/shirudo/map-export.env``.

#. Write the variables your collector needs to
   ``/etc/shirudo/map-export.env``:

   .. code-block:: text

      OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer%20<token>
      OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/shirudo/collector-ca.pem

   ``OTEL_EXPORTER_OTLP_HEADERS`` takes comma-separated
   ``<key>=<value>`` pairs with percent-encoded values, so ``%20`` is a
   space. It refuses ``Content-Type``, ``Content-Encoding``,
   ``Content-Length``, ``Host`` and ``User-Agent``.
   ``OTEL_EXPORTER_OTLP_CERTIFICATE`` names the CA bundle that signed
   the collector's certificate. ``<token>`` is your collector's ingest
   token.

#. Make the file readable by root alone:

   .. code-block:: console

      target# chmod 0600 /etc/shirudo/map-export.env

The target also reads these variables:

- ``OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`` and
  ``OTEL_EXPORTER_OTLP_CLIENT_KEY`` for mutual TLS, both or neither
- ``OTEL_EXPORTER_OTLP_COMPRESSION``: ``none`` or ``gzip``
- ``OTEL_EXPORTER_OTLP_TIMEOUT``: milliseconds per attempt, 1 to 120000,
  default 10000
- ``OTEL_EXPORTER_OTLP_PROTOCOL``: only ``http/json`` is accepted
- ``AWS_REGION`` or ``AWS_DEFAULT_REGION``, ``AWS_ACCESS_KEY_ID``,
  ``AWS_SECRET_ACCESS_KEY``, ``AWS_SESSION_TOKEN``,
  ``AWS_ENDPOINT_URL_S3`` and ``AWS_CA_BUNDLE`` for ``map_export.s3_uri``

Each ``OTEL_EXPORTER_OTLP_*`` variable also has a ``_LOGS_`` and a
``_METRICS_`` form, which wins over the generic one for its signal.
:doc:`/reference/environment` lists them all.

The endpoint variables behave differently for the two services:

- ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` and ``OTEL_EXPORTER_OTLP_ENDPOINT``
  apply only while ``map_export.otel_endpoint`` is empty.
- The keepalive sends when ``map_export.otel_endpoint`` or one of those
  two variables is set. It never falls back to ``localhost``.
- ``upatch map --all`` sends OTLP only when ``map_export.otel_endpoint``
  is set. An endpoint variable alone does not turn the map export on.

``/etc/shirudo/map-export.env`` is host state outside the signed
config, and root on the target can change it. While the signed config
names no endpoint, the file decides where keepalives go. Set the
endpoint in the signed config.

Set up the collector
--------------------

The target speaks OTLP/HTTP with JSON bodies and nothing else:
``POST <base>/v1/logs`` and ``POST <base>/v1/metrics`` with
``Content-Type: application/json``, optional ``Content-Encoding: gzip``
and ``X-Tenant-ID``. It uses TLS 1.3 with the hybrid key exchange groups
``X25519MLKEM768`` and ``SecP256r1MLKEM768`` only. A collector that
offers no hybrid group is refused, unless its exact DNS name is in
``tls.classical_hosts`` in the runtime image's
``etc/shirudo/shirudo.conf``, which takes a new runtime image and a
reboot.

#. Configure the OpenTelemetry Collector's ``otlp`` receiver with TLS:

   .. code-block:: yaml

      receivers:
        otlp:
          protocols:
            http:
              endpoint: 0.0.0.0:4318
              tls:
                cert_file: /etc/otelcol/collector.crt
                key_file: /etc/otelcol/collector.key
                min_version: "1.3"

      exporters:
        debug:
          verbosity: detailed

      service:
        pipelines:
          logs:
            receivers: [otlp]
            exporters: [debug]
          metrics:
            receivers: [otlp]
            exporters: [debug]

   The ``debug`` exporter prints what arrives. Replace it with the
   exporters for your storage once records arrive;
   :doc:`/operate/integrations/index` sets up ClickHouse, Elasticsearch,
   Grafana and Splunk. A collector built with Go 1.24 or later offers
   ``X25519MLKEM768`` by default.

#. Restart the collector. Keep the keepalive body a string on its way
   to storage: a processor that parses it into a structure or rewrites
   it breaks the quote.

Any HTTPS server that accepts those two requests works as a destination.
It answers ``200`` to accept. A ``200`` whose ``partialSuccess`` reports
rejected records counts as a failure. The target retries timeouts,
connection errors and the statuses ``429``, ``502``, ``503`` and
``504``, honors ``Retry-After``, and does not retry any other status.

Check the pipeline
------------------

#. Print the keepalive body the target reports, without quoting or
   sending it:

   .. code-block:: console

      target# shirudo status --keepalive

#. Send one keepalive by hand:

   .. code-block:: console

      target# shirudo status --otel

   The command prints nothing. When no TPM answers or the quote fails,
   it prints ``status: quote the keepalive: <reason>; nothing is sent``
   and exits 1. When the send fails, it prints ``status: send the
   keepalive: <reason>`` and exits 1. When no endpoint is configured, it
   sends nothing and exits 0.

#. Check that the collector printed a record with the event name
   ``shirudo.keepalive``, a ``stringValue`` body and the one attribute
   ``shirudo.quote``.

#. List the maps the loaded upatches pin:

   .. code-block:: console

      target# shirudo upatch map
      Pinned maps (0):
        none

   This target has no upatch with maps loaded. With maps, the command
   lists each map with its upatch, type and size.

#. Look at one map without draining it and without exporting it:

   .. code-block:: console

      target# shirudo upatch map <upatch> <map> --peek

   ``<upatch>`` and ``<map>`` are names from the list. ``--peek`` asks
   the serializer for the interval it is collecting and leaves it for
   the timer.

#. Check that the timers run:

   .. code-block:: console

      target# systemctl list-timers 'shirudo-*'

Map export without a destination
--------------------------------

``shirudo-map-export.timer`` runs whether or not a destination is
configured. With no ``map_export.json_path`` and no
``map_export.otel_endpoint``, every run reads every pinned map, drains
the maps that have a serializer, and prints the dump to its standard
output, which systemd writes to the journal. That happens every 5
seconds, and drained records are gone for any later exporter.

If nothing consumes map snapshots, stop the timer:

.. code-block:: console

   target# systemctl disable --now shirudo-map-export.timer

Maps and decoders
-----------------

A map whose upatch ships a signed decoder for it exports what the
decoder returns, a log record or metrics. A map without a decoder
exports as a log record whose body lists the map's entries.

One kind of map without a decoder fails: a per-CPU map whose value is an
unsigned BTF integer. The target classifies it as a metric, finds no
decoder to build the metric and prints ``upatch map: OTLP export
<upatch>/<map>: No data available``. Give such a map a decoder.
:doc:`/upatches/write/decoders` shows how.

What to alert on
----------------

The keys below are those of the keepalive body,
:doc:`/reference/cli/status` lists them and
:doc:`/operate/run/read-status` explains what each condition and verdict
means. What only the full report carries, such as the size of the
eventlog, is read with ``shirudo status --json`` on the target.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Signal
     - What it means
   * - No keepalive from a host for several intervals
     - The target is down or unreachable, the timer or its drop-in is
       missing, or the commands fail. A keepalive also fails when
       another ``shirudo`` command holds the config operation lock for
       more than 30 seconds, during a long package download for
       example.
   * - ``verdict`` other than ``ok``
     - Read :doc:`/operate/run/read-status` for each verdict.
       ``reboot-pending`` is a config activation that waits for a
       reboot; every command except ``status`` and ``image status`` is
       refused until then.
   * - A pair of ``cond`` at ``11``, ``ALERT``
     - ``LsmAttached``, ``KeyringSealed``, ``ChainIntact``,
       ``UpatchesMeasured`` or ``ConfigActive`` found tampering or lost
       enforcement. ``ChainIntact`` at ``ALERT`` is a register the
       eventlog does not explain; handle it as in
       :doc:`/operate/troubleshoot/incident-tampered`.
   * - ``XdpCovered``, the seventh pair of ``cond``, at ``10``, ``WARN``,
       in several keepalives
     - A device an XDP upatch selects runs without it: its driver
       refuses the program or its XDP was turned off. Each reconcile
       pass retries it at a cost to the target until the device changes
       or the upatch is unloaded. Alert on it, and end it as
       :doc:`/operate/run/read-status` describes.
   * - A counter of ``tamper`` rises
     - Something on the target tried an operation the guards refused.
       The counters start at zero each boot. See
       :doc:`/security/tamper-counters`.
   * - A counter of ``integrity`` rises
     - Something on the target tried to change or read the running
       kernel, and ``bpf2`` refused it. The counters start at zero each
       boot. See :doc:`/security/integrity-counters`.
   * - Bit 0 of ``flags``, ``register_rebound``
     - The register was bound twice in one TPM reset.
   * - Bit 1 of ``flags``, ``bound_late``
     - ``init`` bound the register from the root file system, not from
       the initrd.
   * - Bit 2 of ``flags``, ``tree_log_mismatch``
     - The tree eventlog or the outcomes record does not agree with the
       tree state.
   * - ``version_id`` is not the build you deployed
     - The target runs another shirudo build.

Limits
------

- A map snapshot has no proof of origin. Root on a target, or anyone who
  can reach the collector with valid credentials, can send records in a
  target's name. A keepalive's quote ties its body to an attestation
  key, but a key in software can sign a quote too, so a backend that
  has not tied the key to the target's TPM treats the target as
  untrusted. Use :doc:`/operate/run/attest` for evidence.
- While the config cannot be verified, ``status`` uses only the runtime
  image's settings and the environment. While an activation is pending,
  it uses the pending config's settings only when that config is the one
  mounted. To keep keepalives arriving in those states, also set
  ``OTEL_EXPORTER_OTLP_ENDPOINT`` in ``/etc/shirudo/map-export.env``.
  The map export is refused in those states.
- The keepalive interval is 60 seconds after the previous run ends, not
  a fixed schedule. Size the alert for a missing keepalive to several
  intervals plus the 30-second lock wait, and to the longest tree sync
  your targets run.

Next steps
----------

- :doc:`/operate/run/read-status` to read what the keepalive carries
- :doc:`/reference/formats/otlp` for the records on the wire
- :doc:`/upatches/write/decoders` to give a map a decoder
- :doc:`/reference/cli/upatch-map` and :doc:`/reference/cli/status` for
  every option
- :doc:`/operate/run/attest` for evidence that the target cannot forge
