..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

OTLP documents
==============

shirudo sends OpenTelemetry data as OTLP/HTTP JSON. Each document is
one ``POST`` from a one-shot command:

.. list-table::
   :header-rows: 1
   :widths: 34 26 40

   * - Document
     - Sent by
     - Signal
   * - :doc:`Status keepalive <keepalive>`
     - ``shirudo status --otel``
     - One log record
   * - :doc:`Map snapshot <map-export>`
     - ``shirudo upatch map --otel``, ``shirudo upatch map --all``
     - One log record or the decoder's metrics, per map
   * - :doc:`Map snapshot reference <map-export>`
     - The same, when a snapshot goes to S3
     - One log record

The timers ``shirudo-keepalive.timer`` and ``shirudo-map-export.timer``
run these commands, see :doc:`/reference/systemd-units`. Setting up an
export is in :doc:`/operate/run/telemetry`. Decoders are in
:doc:`/upatches/write/decoders`.

Transport
---------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Property
     - Value
   * - Protocol
     - OTLP/HTTP with JSON bodies. ``OTEL_EXPORTER_OTLP_PROTOCOL`` may
       only be ``http/json``.
   * - Paths
     - ``v1/logs`` for logs, ``v1/metrics`` for metrics, appended to a
       base URL.
   * - Headers
     - ``Content-Type: application/json``,
       ``Content-Encoding: gzip`` when compression is on,
       ``User-Agent: shirudo OTel-OTLP-Exporter-C/1``, the configured
       headers and ``X-Tenant-ID``.
   * - Compression
     - ``none`` (default) or ``gzip``.
   * - TLS
     - TLS 1.3 only, hybrid ML-KEM key exchange
       (``X25519MLKEM768``, ``SecP256r1MLKEM768``). A host listed in
       ``tls.classical_hosts`` may also use ``X25519`` and
       ``secp256r1``, see :doc:`/reference/configuration`.
   * - Cleartext
     - ``http://`` only to ``localhost``, ``127.0.0.1`` or ``[::1]``,
       unless insecure mode is on. Other schemes are refused.
   * - Insecure mode
     - ``--otel-insecure`` or ``map_export.otel_insecure = true``
       allows ``http://`` to any host and turns off certificate and
       host name verification for ``https://``. shirudo prints a
       warning for each export.
   * - Credentials in the URL
     - Refused.
   * - Timeout
     - Per attempt, ``OTEL_EXPORTER_OTLP_TIMEOUT`` in milliseconds, 1
       to 120000, default 10000.
   * - Success
     - HTTP ``200`` only, unless the response reports
       ``partialSuccess`` with ``rejectedLogRecords`` or
       ``rejectedDataPoints`` above zero.
   * - Retries
     - ``map_export.otel_retries`` or ``--otel-retries``, 0 to 10,
       default 3, after the first attempt. Retried: HTTP ``429``,
       ``502``, ``503``, ``504``, and failures to resolve, connect,
       send or receive, and timeouts. Any other response fails at
       once.
   * - Backoff
     - The response's ``Retry-After``, at most 30 seconds, else a
       random delay up to 250 ms doubled per retry, at most 4 s.
   * - Response size
     - A response body over 65535 bytes fails the export.
   * - Request size
     - ``map_export.otlp_max_bytes``, default 4194304, at most
       8388608, before compression. A larger document fails with
       ``E2BIG``.

Endpoint
--------

shirudo picks the first that is set:

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Source
     - URL used
   * - ``--otel-endpoint=<url>`` (``upatch map`` only)
     - ``<url>`` plus the signal path
   * - ``map_export.otel_endpoint`` (``status --otel`` and
       ``upatch map --all``)
     - The value plus the signal path
   * - ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``,
       ``OTEL_EXPORTER_OTLP_METRICS_ENDPOINT``
     - The value as given
   * - ``OTEL_EXPORTER_OTLP_ENDPOINT``
     - The value plus the signal path
   * - None (``upatch map`` only)
     - ``http://localhost:4318`` plus the signal path

The signal path goes before any ``?`` or ``#`` and gets a ``/`` when
the base does not end in one. An empty variable counts as unset.
``status --otel`` sends no keepalive without one of the first four
sources. ``upatch map`` reads the ``map_export.*`` settings only with
``--all``. While a config activation is pending or cannot be verified,
the config image's ``map_export.*`` settings are not in effect and only
the environment can name the endpoint.

Environment
-----------

For each ``OTEL_EXPORTER_OTLP_<setting>`` below, the signal variable
``OTEL_EXPORTER_OTLP_LOGS_<setting>`` or
``OTEL_EXPORTER_OTLP_METRICS_<setting>`` takes precedence. The systemd
services read them from ``/etc/shirudo/map-export.env``.

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Variable
     - Value
   * - ``OTEL_EXPORTER_OTLP_ENDPOINT``
     - Base URL, see `Endpoint`_.
   * - ``OTEL_EXPORTER_OTLP_PROTOCOL``
     - ``http/json``
   * - ``OTEL_EXPORTER_OTLP_COMPRESSION``
     - ``none`` or ``gzip``
   * - ``OTEL_EXPORTER_OTLP_HEADERS``
     - ``<name>=<value>[,<name>=<value>...]``, at most 16384 bytes.
       Blanks around names and values are dropped and values are
       percent-decoded. Refused: a name that is not an HTTP token (RFC
       9110), a value that holds a control character other than tab
       before or after decoding, ``%00`` included, and the names
       ``Content-Type``, ``Content-Encoding``, ``Content-Length``,
       ``Host`` and ``User-Agent``. One ``X-Tenant-ID`` is allowed and
       must be a valid tenant id. A tenant id from the command line or
       the config replaces it.
   * - ``OTEL_EXPORTER_OTLP_CERTIFICATE``
     - CA bundle for the collector's certificate.
   * - ``OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE``,
       ``OTEL_EXPORTER_OTLP_CLIENT_KEY``
     - Client certificate and key for mutual TLS. Both or neither.
   * - ``OTEL_EXPORTER_OTLP_TIMEOUT``
     - Milliseconds, 1 to 120000.

A tenant id, from ``--tenant-id=<id>`` or ``map_export.tenant_id``, is 1
to 128 characters from ``A-Z``, ``a-z``, ``0-9``, ``.``, ``_`` and
``-``. shirudo sends it as ``X-Tenant-ID``.

.. _otlp-resource-scope:

Resource and scope
------------------

Every document has one resource and one scope.

.. list-table::
   :header-rows: 1
   :widths: 34 66

   * - Field
     - Value
   * - Resource attribute ``service.name``
     - ``shirudo``
   * - Resource attribute ``service.version``
     - The version string without the extra version and release name
       that ``shirudo version`` adds, for example ``58d3fa7`` where
       ``shirudo version`` prints ``shirudo (58d3fa7-rc0, ...)``.
   * - Resource attribute ``host.name``
     - The host name, or ``unknown``.
   * - Scope ``name``
     - ``shirudo.keepalive`` for the keepalive,
       ``shirudo.upatch.maps`` for map documents.
   * - Scope ``version``
     - Same as ``service.version``.

Attribute values follow the OTLP JSON encoding: ``stringValue``,
``intValue`` as a decimal string, ``boolValue``.

This page gives what every document shares: the transport, the endpoint,
the environment and the resource. :doc:`keepalive` and :doc:`map-export`
give the documents.

Related
-------

- :doc:`keepalive`
- :doc:`map-export`
- :doc:`/operate/run/telemetry`
- :doc:`/reference/cli/status`
- :doc:`/reference/cli/upatch-map`
- :doc:`/upatches/write/decoders`
- :doc:`/reference/configuration`
