..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Telemetry export
================

shirudo pushes what it knows about a target to a collector; nothing
connects in.  Two things are exported: snapshots of the maps the loaded
upatches maintain, as OTLP logs and metrics, and a periodic status
keepalive, as an OTLP log.  Both leave the target as OTLP/HTTP JSON
documents, POSTed by a one-shot command that a systemd timer runs, so
the target keeps its agentless shape: no exporter daemon, no listening
port, nothing to connect to.

This document describes how a BPF map becomes a record, the decoders
that give a record its shape, the documents on the wire, the transport
and its configuration, and how to land the data in the OpenTelemetry
Collector, ClickHouse, Splunk or a collector of your own.

1) The pipeline
---------------

::

    BPF map (arena, hash, array, per-CPU, ...)
          |
          |  serializer under BPF_PROG_TEST_RUN   (serializer-backed maps)
          |  or a direct read of the pinned map   (other map types)
          v
    4 KiB pages of serialized records, or the raw entries
          |
          |  signed Lua decoder in LuaJIT, or the automatic classifier
          v
    OTLP log record or metric
          |
          |  OTLP/HTTP JSON: POST /v1/logs, POST /v1/metrics
          v
    collector  -->  ClickHouse, Splunk, a database, a custom sink

Every stage runs inside ``shirudo upatch map``.  The command reads the
pins under ``/run/shirudo/bpffs/upatches/<name>/maps/``, uses only
the ``bpf()`` commands the LSM allows from userspace (``OBJ_GET``,
``OBJ_GET_INFO_BY_FD``, ``MAP_LOOKUP_ELEM``, ``MAP_GET_NEXT_KEY``,
``PROG_TEST_RUN``), decodes, and then prints, appends JSON lines to a
file, or exports.  Decoders travel inside the signed ``.upatch``; the
exporter is part of the ``shirudo`` binary.  A snapshot therefore has
the same provenance as the program that produced it.  Reading a serializer-backed map drains
it, exactly as the timer does, because the serializer hands over what
it collected since the previous read; ``upatch map --peek`` asks for
the interval still being collected and leaves it for the exporter.

2) From a map to a record
-------------------------

Serializer-backed maps.  A structure that lives in a BPF arena or
spans several maps (a tree, a ring, a hash of lists) cannot be read
consistently from userspace one element at a time.  An upatch that
owns such a structure also ships a serializer: a ``SEC("syscall")``
program named ``shirudo_serialize__<map>`` that walks the structure in
kernel context, with the ordering and locking the structure needs, and
writes fixed-size records into 4096-byte chunks of a reserved output
map.  ``upatch map`` runs it under ``BPF_PROG_TEST_RUN`` with a cursor,
repeatedly until the program reports ``done``, and collects the pages.
A serializer is an ordinary program in the signed ``.upatch``; the
attach metadata marks it with role ``1`` and names its target map.

Direct readers.  Plain hash, array and per-CPU maps are read with
``MAP_GET_NEXT_KEY`` and ``MAP_LOOKUP_ELEM`` and presented as a list of
entries with hex keys and values.

Decoders.  The pages or entries are handed to the Lua decoder the
upatch declared for that map, which returns the record to export.  A
map without a decoder goes through the automatic classifier: an
unsigned per-CPU BTF integer scalar map becomes a metric named
``shirudo.<upatch>.<map>``, a monotonic cumulative sum with one
``asInt`` data point per key and the key as the ``shirudo.map.key``
attribute; every other map becomes a log record whose body carries the
entries.

3) Decoders
-----------

A decoder is a Lua function shipped inside the upatch.  The BPF source
declares it in ``.rodata`` with a ``struct shirudo_decoder_manifest``:
a magic and version, ``language`` (``1`` is Lua), ``api_version``,
``input_format`` (``1`` is serializer pages), ``export_signal`` (``1``
log, ``2`` metric), and the fixed-size strings ``upatch``, ``map``,
``source`` (the ``.lua`` path, relative to the BPF source) and
``entrypoint`` (``decode``).  At build time ``shirudo-build`` resolves
``source`` and embeds the file in the ``data`` section ahead of the
signature (the decoder trailer in `upatch-spec <upatch-spec.rst>`__), so
a decoder is covered by the same ML-DSA signature as the program whose
data it interprets.  A target runs only decoders that arrived this way;
there is no decoder search path and nothing to drop in.

The decoder runs under LuaJIT's interpreter with an instruction budget
and a memory limit, from source only, never bytecode.  It has the
standard library less what could reach the host, catch the budget's
error or run outside it: ``io``, ``os``, ``package``, ``require``,
``debug``, ``jit``, ``ffi``, the loaders, ``collectgarbage``,
``pcall``, ``xpcall``, ``coroutine``, ``newproxy``, ``print``,
``getfenv``, ``setfenv`` and ``string.find``, ``match``, ``gmatch``,
``gsub`` and ``dump`` are absent.  Its entry point receives one
table::

    input.schema, input.upatch, input.map
    input.startTimeUnixNano, input.timeUnixNano
    input.data.name, input.data.type, input.data.max_entries,
    input.data.n_entries, input.data.key_size, input.data.value_size,
    input.data.n_cpus, input.data.truncated
    input.data.entries[i].key_hex, .value_hex                -- direct reads
    input.data.serialized, input.data.serialized_pages,
    input.data.serialized_bytes
    input.data.pages[i].page_index, .cursor, .next_cursor, .done,
                       .flags, .chunks, .bytes, .data_hex        -- serializer

and a host API for the common case of fixed-size records::

    local slots = shirudo.page_slots(page, slot_size)
    slots[1]:u32(0)             -- every slot of one page in order, the
    slots[2]:u64(16)            -- page header first; u8, u16, u32, u64
    slots[2]:cstring(96, 32)    -- and cstring read at an offset
    local records = shirudo.fixed_records(input.data.pages, slot_size)
    records[2]:u64(0)           -- the older flat view across pages,
                                -- indexed by page cursor plus slot
    shirudo.u64_add(a, b)       -- exact arithmetic on the decimal u64
    shirudo.u64_sub(a, b)       -- strings u64() returns; Lua numbers
    shirudo.hex_u64(hex, off)   -- lose nanoseconds; little-endian u64
                                -- at a byte offset of a hex string

``u64()`` and the arithmetic helpers exchange decimal strings because a
Lua number cannot hold a nanosecond timestamp.  A serializer stamps the
page header with the boot-time clock at the moment it ran, so a decoder
turns a record's boot-time timestamp ``ts`` into wall clock with
``shirudo.u64_sub(input.timeUnixNano, shirudo.u64_sub(boot_now, ts))``.

Return contract.  A log decoder returns a table; it becomes the
``body`` of the log record as an OTLP key-value list, nested tables
becoming nested lists and arrays becoming arrays.  A metric decoder
returns a list of OTLP ``Metric`` objects, exactly as they appear in
the ``metrics`` array of a ``scopeMetrics`` entry, so the decoder
decides the name, unit, description, aggregation and data points.  An
error raised in the decoder drops that snapshot with a diagnostic; it
never produces a partial record.  Strings go out as UTF-8, with U+FFFD
in place of a byte sequence that is not, such as a name the kernel
cut mid-character.  The shipped
``upatches/kernel-obs/decoders/watch_stat.lua`` turns a per-CPU
counter pair into one monotonic sum with two labelled points::

    local function metric_point(input, value, outcome)
        return {
            startTimeUnixNano = input.startTimeUnixNano,
            timeUnixNano = input.timeUnixNano,
            asInt = value,
            attributes = {
                {key = "outcome", value = {stringValue = outcome}},
            },
        }
    end

    function decode(input)
        local data = input.data
        local entry = data.entries and data.entries[1]
        if not entry then
            error("missing watch counter entry")
        end
        local stride = math.ceil((data.value_size or 16) / 8) * 8
        local checked, matched = "0", "0"
        for cpu = 0, (data.n_cpus or 1) - 1 do
            local base = cpu * stride
            checked = shirudo.u64_add(checked,
                shirudo.hex_u64(entry.value_hex, base))
            matched = shirudo.u64_add(matched,
                shirudo.hex_u64(entry.value_hex, base + 8))
        end
        return {
            {name = "kernel_obs.watch_attempts", unit = "1",
             description = "socket-level destination checks against the watch list",
             sum = {
                 aggregationTemporality = 2,
                 isMonotonic = true,
                 dataPoints = {
                     metric_point(input, checked, "checked"),
                     metric_point(input, matched, "matched"),
                 },
             }},
        }
    end

The ``kernel-obs`` package carries decoders for its exec, net, listen,
watch, dns, priv and file tables; they are the reference for writing new
ones, the timestamp conversion included.

4) The documents on the wire
----------------------------

Every export is an OTLP/HTTP JSON document (``application/json``,
gzip-compressed when enabled).  The resource carries
``service.name = shirudo`` and ``host.name``; the instrumentation scope
is ``shirudo.upatch.maps`` with the shirudo version.

Map snapshot log, one ``logRecord`` per map::

    eventName             shirudo.bpf.map.snapshot
    severityNumber/Text   9 / INFO
    body                  the decoder's table, or the entries
    attributes            shirudo.upatch.name, shirudo.upatch.location,
                          shirudo.map.name, shirudo.map.type,
                          shirudo.map.max_entries, shirudo.map.n_entries,
                          shirudo.map.n_cpus, shirudo.map.serialized,
                          shirudo.map.truncated

Map metric, one ``Metric`` per map or per decoder entry under the same
resource and scope.

Keepalive, one log record from ``shirudo status --otel``::

    eventName             shirudo.keepalive
    severityNumber/Text   9 / INFO     status ok
                          13 / WARN    degraded, init-pending
                          17 / ERROR   lsm-off, tampered
    body                  the status --json document as a key-value
                          list (schema, status, conditions, tpm,
                          tamper_attempts, system, ...)
    attributes            shirudo.status, shirudo.version_id,
                          shirudo.tamper_attempts (the total of the
                          refusals the guards counted this boot)

The keepalive is sent only when an endpoint is configured explicitly,
through ``map_export.otel_endpoint`` or the
``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` or ``OTEL_EXPORTER_OTLP_ENDPOINT``
variables; it never falls back to localhost.  A collector that stops
receiving keepalives from a host, or receives one at ERROR, has the two
signals an operator needs most.

S3 reference.  With ``--s3-uri`` (or ``map_export.s3_uri``) the
snapshot itself is uploaded and the log record becomes a pointer::

    eventName             shirudo.bpf.map.snapshot.reference
    attributes            shirudo.map.snapshot.uri, .size_bytes,
                          .uncompressed_size_bytes, .format,
                          .content_type, .content_encoding,
                          plus the map attributes above

The object key is ``<prefix>/<hostname>/<upatch>/<map>/<sha256>.json.gz``
with ``x-amz-meta-shirudo-schema``, ``-upatch`` and ``-map`` metadata,
signed with SigV4 from ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``,
``AWS_SESSION_TOKEN``, ``AWS_REGION`` or ``AWS_DEFAULT_REGION``, and
``AWS_CA_BUNDLE``.  Large snapshots bypass the collector's record size
limits this way while the collector still learns that they exist.

JSON lines.  ``--json`` prints the map listing or decoded records to
stdout.  ``--json=<path>`` (or ``map_export.json_path``) appends them
as JSON lines to a file for a log shipper that tails files.

5) Transport
------------

Endpoint.  ``--otel-endpoint=<base>`` sends logs to ``<base>/v1/logs``
and metrics to ``<base>/v1/metrics``.  Without it the standard
variables apply: ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` and
``OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`` are used verbatim,
``OTEL_EXPORTER_OTLP_ENDPOINT`` gets the path appended, and the default
is ``http://localhost:4318``.  For every setting below the
signal-specific variable (``_LOGS_`` or ``_METRICS_``) wins over the
generic one.  ``OTEL_EXPORTER_OTLP_PROTOCOL`` may be set to
``http/json``; any other value is refused, shirudo speaks nothing else.

Headers.  ``OTEL_EXPORTER_OTLP_HEADERS`` (``key=value,key=value``) adds
headers to every request, which is how an ingest token reaches a hosted
collector.  ``--tenant-id`` or ``map_export.tenant_id`` sets
``X-Tenant-ID``; a tenant id is 1 to 128 characters of letters, digits,
``.``, ``_`` and ``-``.  ``OTEL_EXPORTER_OTLP_COMPRESSION=gzip``
compresses the body.

TLS.  Like every libcurl client in shirudo, the exporter speaks TLS 1.3
with a hybrid ML-KEM key exchange only (X25519MLKEM768,
SecP256r1MLKEM768); a collector that offers only classical groups is
refused.  ``OTEL_EXPORTER_OTLP_CERTIFICATE`` names a CA bundle,
``OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`` and
``OTEL_EXPORTER_OTLP_CLIENT_KEY`` a client certificate for mutual TLS.
Cleartext ``http://`` is allowed only to loopback.  ``--otel-insecure``
(``map_export.otel_insecure``) permits cleartext to other hosts and
disables certificate verification for ``https://``, with a warning each
time; it exists for test rigs.

Retries.  ``OTEL_EXPORTER_OTLP_TIMEOUT`` (milliseconds, default 10000)
bounds each attempt.  A transport error and the responses OTLP calls
retryable, 429, 502, 503 and 504, are retried with exponential backoff
from 250 ms, honouring ``Retry-After`` up to 30 s, for
``--otel-retries`` attempts (``map_export.otel_retries``, default 3,
at most 10).  Any other 4xx or 5xx response is not retried.  A 200
whose ``partialSuccess`` rejected records is a non-retryable failure,
so a collector that drops records is reported rather than silently
accepted; one that rejected none only carries a warning.

Limits.  A record larger than ``map_export.log_record_max_bytes``
(default 1 MiB) and a request larger than ``map_export.otlp_max_bytes``
(default 4 MiB) are refused with a diagnostic, never truncated; the S3
path exists for snapshots that are legitimately larger.

6) Configuration and timers
---------------------------

``/etc/shirudo/shirudo.conf``::

    map_export.json_path = /var/log/shirudo/maps.ndjson
    map_export.otel_endpoint = https://collector.example:4318
    map_export.tenant_id = fleet-eu-1
    map_export.otel_insecure = false
    map_export.otel_retries = 3
    map_export.s3_uri = s3://bucket/prefix
    map_export.log_record_max_bytes = 1048576
    map_export.otlp_max_bytes = 4194304

Command-line options override the file; ``shirudo config`` prints the
effective values.  Headers, TLS material and credentials are
environment, not configuration: the timers read
``/etc/shirudo/map-export.env`` for the ``OTEL_EXPORTER_OTLP_*`` and
``AWS_*`` variables.

``shirudo-map-export.timer`` runs ``shirudo upatch map --all`` five
seconds after the previous run finished, and that command exports to
whatever ``map_export`` names: JSON lines, OTLP, S3, any combination,
or nothing.  ``shirudo-keepalive.timer`` runs ``shirudo status --otel
--include-system`` on the same cadence.  Both are
ordinary one-shot services; disable a timer to stop an export, and
nothing else changes.

7) Integrating with collectors
------------------------------

The OpenTelemetry Collector.  shirudo speaks standard OTLP/HTTP, so the
``otlp`` receiver accepts it unchanged and any exporter can follow.  A
pipeline that lands logs and metrics in ClickHouse and Splunk::

    receivers:
      otlp:
        protocols:
          http:
            endpoint: 0.0.0.0:4318
            tls:
              cert_file: /etc/otelcol/collector.crt
              key_file: /etc/otelcol/collector.key
              min_version: "1.3"

    processors:
      batch:

    exporters:
      clickhouse:
        endpoint: tcp://clickhouse:9000
        database: shirudo
        logs_table_name: upatch_logs
        metrics_table_name: upatch_metrics
      splunk_hec:
        token: "${env:SPLUNK_HEC_TOKEN}"
        endpoint: https://splunk.example:8088/services/collector
        source: shirudo
        sourcetype: otel
        index: shirudo

    service:
      pipelines:
        logs:
          receivers: [otlp]
          processors: [batch]
          exporters: [clickhouse, splunk_hec]
        metrics:
          receivers: [otlp]
          processors: [batch]
          exporters: [clickhouse, splunk_hec]

The collector must offer a hybrid ML-KEM group; Go's TLS stack, which
the collector uses, enables X25519MLKEM768 by default since Go 1.24.
Terminate TLS in a proxy that does if a build cannot.

ClickHouse.  The ``clickhouse`` exporter stores each log record with
its ``Body``, ``SeverityNumber``, ``ResourceAttributes`` and
``LogAttributes`` maps, so the ``shirudo.*`` attributes are map keys::

    -- hosts whose last keepalive is older than a minute
    SELECT ResourceAttributes['host.name'] AS host, max(Timestamp) AS last
    FROM shirudo.upatch_logs
    WHERE LogAttributes['shirudo.status'] != ''
    GROUP BY host HAVING last < now() - INTERVAL 60 SECOND;

    -- hosts that are not ok right now
    SELECT ResourceAttributes['host.name'], LogAttributes['shirudo.status'],
           LogAttributes['shirudo.version_id']
    FROM shirudo.upatch_logs
    WHERE SeverityNumber >= 13 AND Timestamp > now() - INTERVAL 5 MINUTE;

    -- hosts where a guard refused something this boot
    SELECT ResourceAttributes['host.name'] AS host,
           max(toInt64(LogAttributes['shirudo.tamper_attempts'])) AS refused
    FROM shirudo.upatch_logs
    WHERE LogAttributes['shirudo.tamper_attempts'] != ''
    GROUP BY host HAVING refused > 0;

    -- the latest snapshot of one map on one host
    SELECT Body FROM shirudo.upatch_logs
    WHERE LogAttributes['shirudo.upatch.name'] = 'kernel-obs'
      AND LogAttributes['shirudo.map.name'] = 'exec'
      AND ResourceAttributes['host.name'] = 'node-17'
    ORDER BY Timestamp DESC LIMIT 1;

Metrics land in the exporter's sum and gauge tables, keyed by the
metric name (``shirudo.<upatch>.<map>`` or the decoder's) and its
attributes.

Splunk.  The ``splunk_hec`` exporter turns each log record into an HEC
event with the body as the event and the attributes as fields, so
``shirudo.status``, ``shirudo.upatch.name`` and ``shirudo.map.name``
are searchable, ``index=shirudo shirudo.status!=ok`` lists the
unhealthy hosts and ``index=shirudo shirudo.tamper_attempts>0`` the
hosts where a guard refused something.  Metrics go to a metrics index through the same
exporter.  An HEC endpoint can also be the direct target of a custom
sink as described below.

A collector of your own.  shirudo needs nothing collector-specific.
Any HTTPS server that accepts two requests is a valid destination::

    POST <base>/v1/logs       Content-Type: application/json
    POST <base>/v1/metrics    Content-Encoding: gzip        (when enabled)
                              X-Tenant-ID: <tenant>         (when set)
                              plus OTEL_EXPORTER_OTLP_HEADERS

    200 {}                                  accepted
    200 {"partialSuccess": {...}}           rejected, not retried, when
                                            it rejected records
    429, 502, 503, 504, timeout,            retried with backoff;
    connection error                        Retry-After honoured
    other 4xx and 5xx                       rejected, not retried

The body is the OTLP ``ExportLogsServiceRequest`` or
``ExportMetricsServiceRequest`` in its JSON encoding:
``resourceLogs[].scopeLogs[].logRecords[]`` and
``resourceMetrics[].scopeMetrics[].metrics[]``.  A sink is a few dozen
lines in any language; ``testing/helper/otel-mock.py`` in the tree is one,
used by the exporter tests, and shows the three response modes above.
Point shirudo at it with ``--otel-endpoint`` and watch the documents
arrive.

Without a network.  ``map_export.json_path`` appends JSON lines that
any file-tailing shipper picks up (the collector's ``filelog``
receiver, Vector, Fluent Bit, a Splunk forwarder), and ``shirudo status
--json`` and ``--report=<path>`` produce files the same way.
Air-gapped fleets use this path.

8) Checking a pipeline
----------------------

On a target::

    sudo shirudo upatch map --all                           # decoded, to stdout
    sudo shirudo upatch map --all --json                    # decoded NDJSON
    sudo shirudo upatch map --all --json=/tmp/maps.ndjson  # JSON lines
    sudo shirudo upatch map --all --otel --otel-endpoint=http://127.0.0.1:4318
    sudo shirudo status --otel --include-system

Every refusal is logged to syslog under the ``shirudo`` tag with the
HTTP status or curl error, the attempt count and the endpoint.  On the
collector side, the ``debug`` exporter prints what arrived.
