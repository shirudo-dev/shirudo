..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Map logs and metrics
====================

What ``shirudo upatch map --otel`` and ``shirudo upatch map --all``
export from a upatch's maps: a log record or the decoder's metrics per
map, a reference to a snapshot stored in S3, or a line of JSON. The
transport, the endpoint and the resource it shares with the keepalive
are in :doc:`otlp`.

Map snapshot log
----------------

One log record per map:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Field
     - Value
   * - ``timeUnixNano``, ``observedTimeUnixNano``
     - Wall clock when shirudo builds the document, nanoseconds since
       the epoch, decimal string.
   * - ``severityNumber``, ``severityText``
     - ``9``, ``INFO``
   * - ``eventName``
     - ``shirudo.bpf.map.snapshot``
   * - ``body``
     - The value the map's decoder returns, as an OTLP value. Without a
       decoder, a ``kvlistValue`` of the map's contents, see
       `Undecoded body`_.
   * - Attribute ``shirudo.upatch.name``
     - The upatch name.
   * - Attribute ``shirudo.upatch.location``
     - The upatch's attach point.
   * - Attribute ``shirudo.map.name``
     - The map name.
   * - Attribute ``shirudo.map.type``
     - The map type name.
   * - Attribute ``shirudo.map.max_entries``
     - Integer.
   * - Attribute ``shirudo.map.n_entries``
     - Integer, entries read.
   * - Attribute ``shirudo.map.n_cpus``
     - Integer.
   * - Attribute ``shirudo.map.serialized``
     - Boolean, the map was read through its serializer.
   * - Attribute ``shirudo.map.truncated``
     - Boolean, the read stopped before the last entry.

A decoded body larger than ``map_export.log_record_max_bytes`` (default
1048576, at most ``map_export.otlp_max_bytes``) fails with ``E2BIG``.

Undecoded body
~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Key
     - Value
   * - ``name``, ``type``, ``max_entries``, ``n_entries``
     - The map.
   * - ``n_cpus``
     - Per-CPU maps only.
   * - ``serialized``
     - Boolean.
   * - ``serialized_pages``, ``serialized_bytes``, ``pages``
     - Serializer-backed maps. Each page has ``page_index``,
       ``cursor``, ``next_cursor``, ``done``, ``flags``, ``chunks``,
       ``bytes`` and ``data_hex``.
   * - ``skipped``
     - The reason, for a map type shirudo cannot read generically.
   * - ``truncated``, ``n_truncated_at``
     - Other maps. ``n_truncated_at`` only when truncated.
   * - ``btf``
     - ``key_type``, ``value_type``, and ``key_type_def`` and
       ``value_type_def`` when known.
   * - ``entries``
     - Each with ``key`` and ``value``, or for per-CPU maps ``key``,
       ``values_per_cpu`` and ``sum``, formatted from BTF.

Map metrics
-----------

A decoder that declares the metric signal returns a list of OTLP
``Metric`` objects. shirudo sends them as
``resourceMetrics[0].scopeMetrics[0].metrics`` under the resource and
scope of :ref:`otlp-resource-scope` and adds no attributes.

Signal selection
~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Map
     - Export
   * - Has a decoder
     - The signal the decoder declares, log or metric.
   * - No decoder, unsigned per-CPU integer value
     - Classified as a metric. Metrics come only from decoders, so the
       export fails with ``ENODATA``.
   * - No decoder, any other map
     - Log record with the undecoded body.

For an undecoded map ``upatch map`` prints the choice on standard
error as ``otel: selected <signal> for <type> map <name>: <reason>``.

S3 snapshots
------------

When a decoded map's document fails with ``E2BIG`` and an S3 URI is
set (``--s3-uri=<uri>`` or ``map_export.s3_uri``), shirudo uploads the
snapshot to S3 and sends a reference log record instead. Undecoded,
skipped and truncated maps are not uploaded.
``map_export.s3_uri`` requires ``map_export.otel_endpoint``.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Property
     - Value
   * - URI
     - ``s3://<bucket>[/<prefix>]``. Bucket: 3 to 63 characters from
       ``a-z``, ``0-9``, ``.`` and ``-``, starting and ending with a
       letter or digit. Prefix: at most 512 bytes, no control
       characters, ``?``, ``#``, ``.`` or ``..`` segments.
   * - Object
     - The decoder's JSON output, gzip-compressed, at most 64 MiB
       before compression.
   * - Key
     - ``[<prefix>/]<host>/<upatch>/<map>/<sha256>.json.gz``.
       ``<host>`` is the host name with every character other than
       ``A-Z``, ``a-z``, ``0-9``, ``-``, ``_`` and ``.`` replaced by
       ``_``. ``<sha256>`` is the digest of the compressed object.
   * - URL
     - With ``AWS_ENDPOINT_URL_S3``: ``<endpoint>/<bucket>/<key>``.
       Else ``https://<bucket>.s3.<region>.amazonaws.com/<key>``, or
       ``https://s3.<region>.amazonaws.com/<bucket>/<key>`` for a
       bucket name with a dot.
   * - Request
     - ``PUT`` signed with AWS SigV4, with ``If-None-Match: *``,
       ``Cache-Control: immutable``, ``x-amz-content-sha256``,
       ``x-amz-checksum-sha256``, ``x-amz-meta-shirudo-schema: 1``,
       ``x-amz-meta-shirudo-upatch`` and ``x-amz-meta-shirudo-map``.
       ``412`` counts as already uploaded.
   * - Timeout and retries
     - 10 seconds per attempt. Retries as for OTLP, also on ``408``,
       ``409`` and ``500``.
   * - Cleartext
     - As for OTLP, for ``AWS_ENDPOINT_URL_S3``. Insecure mode also
       turns off certificate verification for the AWS endpoints.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Variable
     - Value
   * - ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``
     - Required. Missing credentials fail with ``EACCES``.
   * - ``AWS_SESSION_TOKEN``
     - Sent as ``x-amz-security-token``.
   * - ``AWS_REGION``, ``AWS_DEFAULT_REGION``
     - Region, in this order, default ``us-east-1``.
   * - ``AWS_ENDPOINT_URL_S3``
     - S3-compatible endpoint, path-style.
   * - ``AWS_CA_BUNDLE``
     - CA bundle for the S3 endpoint.

The reference log record goes to the logs endpoint, whatever signal
the decoder declares, and is not subject to
``map_export.otlp_max_bytes``:

.. list-table::
   :header-rows: 1
   :widths: 44 56

   * - Field
     - Value
   * - ``eventName``
     - ``shirudo.bpf.map.snapshot.reference``
   * - ``severityNumber``, ``severityText``
     - ``9``, ``INFO``
   * - ``body``
     - ``stringValue``: ``BPF map snapshot stored in S3: <uri>``
   * - Attributes
     - The map snapshot attributes above, and
       ``shirudo.map.snapshot.uri``,
       ``shirudo.map.snapshot.format`` (``shirudo.map.v1+json``),
       ``shirudo.map.snapshot.content_type`` (``application/json``),
       ``shirudo.map.snapshot.content_encoding`` (``gzip``),
       ``shirudo.map.snapshot.size_bytes``,
       ``shirudo.map.snapshot.uncompressed_size_bytes`` and
       ``shirudo.map.snapshot.sha256``.

JSON lines
----------

``map_export.json_path`` or ``upatch map --json=<path>`` appends one line
per map to a file, instead of OTLP or besides it. The line is the JSON
value the map's decoder returns, not an OTLP document. A map without a
decoder has no line: ``upatch map`` reports ``<upatch>/<map> has no
decoder, and --json writes what a decoder returns`` for it and exits 1
once the other maps are handled. ``map_export.json_path`` must be an
absolute path. A file or directory that carries shirudo's seal label is
refused. A new file gets mode ``0644``.

Related
-------

- :doc:`otlp`
- :doc:`/reference/cli/upatch-map`
- :doc:`/upatches/write/decoders`
- :doc:`/operate/run/telemetry`
- :doc:`/reference/configuration`
