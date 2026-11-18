..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Explanation
:audience: All readers

OpenTelemetry and OTLP
======================

shirudo reports the state of a target and the observations of its
upatches to the monitoring an operator already runs. It does so in
OpenTelemetry's data model, over OpenTelemetry's wire protocol, OTLP.
This page explains the parts of OpenTelemetry that shirudo uses, how a
target exports, and what exported telemetry can and cannot tell you.

Why a standard format
---------------------

A fleet's telemetry has to land in whatever the operator uses: a log
store, a time-series database, a SIEM. A format of shirudo's own would
need a receiver written for each of them. A target that served its data
on request would need a listening socket and a process that stays
running, both of which the agentless target avoids.

OpenTelemetry is a vendor-neutral specification for telemetry data and
for the protocol that carries it. Collectors and many backends accept
OTLP directly, so a target that pushes OTLP needs nothing specific to the
backend on the other end.

Signals
-------

OpenTelemetry calls each kind of telemetry a signal. It supports traces,
metrics and logs, and baggage, which carries context between services.

A log record is one event. It carries a timestamp, the time it was
observed, a severity as a number and a text (``9`` is ``INFO``, ``13`` is
``WARN``, ``17`` is ``ERROR``), an optional event name, a body and a set
of attributes. The body is an ``AnyValue``: a string, a number, a
boolean, or arrays and key-value lists of those, so a log record can
carry a structured document.

A metric is a named series of data points with a unit and a description.
A sum adds up values, monotonic or not, and states whether each point
covers the time since the start or since the previous point. A gauge
reports a current value. Each data point has its own timestamps and
attributes.

shirudo emits logs and metrics. It emits no traces.

Resources, scopes and attributes
--------------------------------

Every record belongs to a resource, the entity that produced it,
described by resource attributes such as ``service.name`` and
``host.name``. Within a resource, records are grouped by instrumentation
scope, the name and version of the code that produced them. Each record
then has attributes of its own.

The structure of a request follows that grouping. A logs request holds
``resourceLogs``, each with a ``resource`` and its ``scopeLogs``, each
with a ``scope`` and its ``logRecords``. A metrics request has the same
shape with ``resourceMetrics``, ``scopeMetrics`` and ``metrics``.

OTLP over HTTP
--------------

OTLP sends a request per batch of records: an
``ExportLogsServiceRequest`` or ``ExportMetricsServiceRequest``. Over
HTTP, the client POSTs logs to the path ``/v1/logs`` and metrics to
``/v1/metrics``, by default on port 4318. The body is either binary
protobuf (``application/x-protobuf``) or the protobuf JSON mapping
(``application/json``). In the JSON form, 64-bit integers are decimal
strings and enumerations are integers. The client may compress the body
with gzip and say so in ``Content-Encoding``. OTLP also runs over gRPC.

The server answers ``200`` when it accepted the request. A
``partialSuccess`` object in that answer reports how many log records or
data points it rejected and why. The specification makes ``429``,
``502``, ``503`` and ``504`` retryable and lets the server ask for a delay
with ``Retry-After``.

Exporters are configured through standard environment variables.
``OTEL_EXPORTER_OTLP_ENDPOINT`` is a base URL to which the signal path is
appended, while ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`` and
``OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`` are used as they are. Further
variables set headers, a CA certificate, a client certificate and key,
compression, a timeout and the protocol.

Collector
---------

The OpenTelemetry Collector receives, processes and exports telemetry,
independent of any vendor. Receivers accept data, for example OTLP on
port 4318. Processors batch, filter or enrich it. Exporters send it on to
backends. A pipeline connects them for one signal. A target that sends
to a collector leaves the choice of backend, retention and routing to
the collector's configuration.

How shirudo exports
-------------------

Figure 1 shows the two paths from a target to a collector.

.. figure:: /images/background-telemetry-export.svg
   :alt: Map snapshots pass from a BPF map through a serializer or direct
         read and a signed decoder into OTLP JSON; the keepalive body,
         quoted by the TPM, becomes a keepalive log; both are posted to a
         collector.

   Figure 1. Telemetry export. Two one-shot commands, each started by a
   systemd timer, build OTLP JSON documents and post them to the
   collector. Nothing on the target listens for connections.

``shirudo-keepalive.timer`` runs ``shirudo status --otel``, and
``shirudo-map-export.timer`` runs ``shirudo upatch map --all``. Each
timer starts its service five seconds after boot. The keepalive timer
starts it again a minute after the previous run finished, the map-export
timer five seconds after.

shirudo speaks OTLP over HTTP with the JSON encoding only and refuses an
``OTEL_EXPORTER_OTLP_PROTOCOL`` other than ``http/json``. Every request
carries the resource attributes ``service.name`` (``shirudo``),
``service.version`` and ``host.name``, which is the host name
``gethostname()`` returns.

The keepalive is one log record with the event name
``shirudo.keepalive``. Its body is a string, a compact JSON status
record of about a kilobyte: the verdict, the conditions, the tamper
counters, the build, the config and image, the tree the target follows
and the upatches it has loaded. Its one attribute, ``shirudo.quote``, is
a TPM quote of the SHA-256 of those bytes by the attestation key of
``shirudo attest``. The body travels as a string because a collector may
re-encode a structure, and the quote covers the exact bytes. The
severity follows the verdict: ``INFO`` for ``ok``, ``WARN`` for
``degraded``, ``init-pending`` and ``reboot-pending``, and ``ERROR`` for
every other verdict. ``shirudo status --otel`` sends the keepalive only
when the signed config or the environment names an endpoint, never falls
back to the default ``localhost`` endpoint, and sends nothing when the
TPM does not quote.

A map snapshot goes through the decoder the upatch signed for that map,
which declares whether the map becomes a log record or metrics. A log
record has the event name ``shirudo.bpf.map.snapshot``, the decoder's
table as its body and attributes that name the upatch and the map. A
metric decoder returns the metric objects themselves. A map without a
decoder goes through a classifier. If the classifier picks a log, the
body carries the map's entries as shirudo renders them from BTF, or the
serializer's pages in hex. If it
picks a metric, which it does for an unsigned per-CPU integer, the export
of that map fails, because only a decoder builds metrics.
:doc:`luajit` explains how decoders run.

A decoded snapshot too large for the configured record or request size
can go to S3 storage instead, when ``map_export.s3_uri`` is set. shirudo
uploads the snapshot and sends a log record with the event name
``shirudo.bpf.map.snapshot.reference`` that points to it.

The destination, tenant, retries and size limits are ``map_export.*``
settings in ``etc/shirudo/shirudo.conf`` of the signed config image. Both
units also read ``/etc/shirudo/map-export.env``, which carries the
``OTEL_EXPORTER_OTLP_*`` headers, CA certificate, client certificate and
key, compression and timeout, and the ``AWS_*`` credentials for S3.
:doc:`/reference/configuration` lists the settings, and
:doc:`/reference/formats/otlp` the documents on the wire.

The connection uses TLS 1.3 with a hybrid ML-KEM key exchange, the same
policy as shirudo's other HTTPS connections. A collector that offers only
classical key exchange is refused unless its host name is listed in
``tls.classical_hosts``. Plain ``http://`` is allowed only to a loopback
address, unless ``map_export.otel_insecure`` is set, which also turns off
certificate verification for ``https://``. shirudo retries the retryable
answers and transport errors with backoff, and counts a
``partialSuccess`` that rejected records as a failure.

A serializer-backed map hands over what it collected since the previous
read and, in the double-buffered tables of the shipped ``kernel-obs``
upatch, clears it. ``shirudo upatch map`` reads the map before it sends,
so a failed export loses that interval. There is no spool on the
target.

Limits
------

Map snapshots carry no proof of origin: they are not signed and not
bound to the TPM. The keepalive's quote shows that its body is unchanged
since the attestation key signed it, and its clock orders the
keepalives of one key. It does not show that the key lives in a genuine
TPM, and the body is still what the target reports. The host name in a
document is whatever the host reports. The credentials and the CA certificate for the collector come
from ``/etc/shirudo/map-export.env``, a file root on the target can
change, and ``map_export.otel_insecure`` turns off certificate
verification.

Root on the target can therefore stop the timers, drain a map by running
``shirudo upatch map`` itself, point the keepalive at another collector
when the signed config names none, or have the TPM quote a body of its
own that reports ``ok`` with no refusals. A missing keepalive, or one at
``ERROR``, is worth acting on. A keepalive that reports ``ok`` proves
nothing.

Telemetry is the target's own account of itself. The evidence of what a
target runs is the TPM-signed record that ``shirudo attest`` produces and
``shirudo attest verify`` checks on the operator host, described in
:doc:`/operate/run/attest`. The threat model covers exported telemetry in
:doc:`/security/threat-model`.

Related
-------

- :doc:`/operate/run/telemetry` to set up export on a target
- :doc:`siem-export` for how the records reach a SIEM and what to
  detect with them
- :doc:`/reference/formats/otlp` for the exported documents
- :doc:`/reference/systemd-units` for the timers and services
- :doc:`luajit` for the decoder sandbox
- :doc:`/upatches/write/decoders` for writing a decoder
