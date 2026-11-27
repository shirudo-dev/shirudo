..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

shirudo upatch map
==================

List the pinned maps of the loaded upatches, print one map's contents, or
export maps as JSON lines, OTLP or S3 objects.

Runs on: target, as root with the runtime binary. Requires: loaded
upatches with pinned maps. Changes measured state: no.

Usage
-----

.. code-block:: none

   shirudo upatch map [<upatch>] [--json | --json=<path>]
   shirudo upatch map <upatch> <map> [--json | --json=<path>] [--show-full] [--peek]
                      [--otel [--otel-endpoint=<url>] [--tenant-id=<id>]
                              [--otel-insecure] [--otel-retries=<retries>]
                              [--s3-uri=<uri>]]
   shirudo upatch map --all [--json | --json=<path>] [--show-full] [--peek]
                      [--otel [<otlp-options>]]

``--json`` takes its path after ``=`` only. The other options with a
value take it after ``=`` or as the next argument.

Description
-----------

Listing
~~~~~~~

Without arguments, ``map`` lists every pinned map of every loaded upatch
with its type and maximum number of entries. With ``<upatch>``, it lists the maps of that
upatch. ``--json`` prints the list as ``{"schema":1,"maps":[...]}`` with
``upatch``, ``name``, ``type``, ``max_entries`` and, for a per-CPU map,
``n_cpus`` per map.

One map
~~~~~~~

With ``<upatch> <map>``, ``map`` reads the map:

- A map is decoded through its BTF types when the build kept them
  (``shirudo build`` compiles with ``-g``).
- When the upatch pins a serializer program for the map, ``map`` runs it
  and prints the pages it returns. Such a read drains the serializer:
  records it returns are gone for the next reader, the export timer
  included. ``--peek`` reads the interval being collected without taking
  it.
- The human output shows at most 256 entries unless ``--show-full``.
  JSON and OTLP output have no limit.
- ``--json`` prints one JSON line to standard output. ``--json=<path>``
  appends it to ``<path>``. The line is what the map's signed Lua
  decoder returns (:doc:`/upatches/write/decoders`). A map without a
  decoder has no JSON form: the command prints ``upatch map:
  <upatch>/<map> has no decoder, and --json writes what a decoder
  returns`` and exits 1. The output without ``--json`` needs no decoder.
- ``--otel`` sends the map to an OTLP collector. A map with a signed Lua
  decoder is sent as the log or metric the decoder declares. A map
  without one is classified by shirudo (see
  :doc:`/reference/formats/map-export`).

Every map
~~~~~~~~~

``--all`` handles every map of every loaded upatch as above and loads the
``map_export`` settings (:doc:`/reference/configuration`):
``map_export.json_path`` turns on JSON output to that file and
``map_export.otel_endpoint`` turns on OTLP, together with the tenant,
TLS, retry, size and S3 settings. Options on the command line take
precedence.

With neither a JSON nor an OTLP destination, ``--all`` prints every map in
full detail on standard output, draining every serializer-backed map
unless ``--peek``. ``shirudo-map-export.timer`` runs ``upatch map --all``
every five seconds, so without a configured destination it drains the
maps into the journal.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 22 22 12 44

   * - Option
     - Argument
     - Default
     - Description
   * - ``--all``
     - none
     - off
     - Handle every map of every loaded upatch. Takes no positional
       argument.
   * - ``--json``
     - optional ``<path>`` after ``=``
     - off
     - Print JSON, or append it to ``<path>``.
   * - ``--show-full``
     - none
     - off
     - Lift the 256-entry limit of the human output.
   * - ``--peek``
     - none
     - off
     - Read serializer-backed maps without draining them.
   * - ``--otel``
     - none
     - off
     - Export through OTLP. Without ``--all`` it needs ``<upatch>`` and
       ``<map>``.
   * - ``--otel-endpoint``
     - ``<url>``
     - ``map_export.otel_endpoint`` with ``--all``, else the
       ``OTEL_EXPORTER_OTLP_*`` variables, else ``http://localhost:4318``
     - OTLP base URL. The signal path is appended.
   * - ``--tenant-id``
     - ``<id>``, 1 to 128 of ``A-Z a-z 0-9 . _ -``
     - ``map_export.tenant_id`` with ``--all``
     - Send an ``X-Tenant-ID`` header.
   * - ``--otel-insecure``
     - none
     - ``map_export.otel_insecure`` with ``--all``
     - Allow cleartext OTLP to a remote host, or turn off HTTPS
       certificate verification.
   * - ``--otel-retries``
     - ``<retries>``, 0 to 10
     - 3
     - Retries after the first attempt.
   * - ``--s3-uri``
     - ``<uri>``
     - ``map_export.s3_uri`` with ``--all``
     - Where to store an OTLP payload that is too large to send.

The OTLP options require ``--otel``. ``--all``, ``--json``, ``--otel`` and
each OTLP option may appear once.

Exit status
-----------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Status
     - Meaning
   * - 0
     - Every map was read and exported.
   * - 1
     - A map could not be read, written as JSON or sent. With ``--all``
       the other maps are still handled. Also, with ``--all``, the
       configuration cannot be loaded.
   * - 2
     - A usage error: an unknown or repeated option, a value missing,
       empty or invalid, positional arguments with
       ``--all``, ``--otel`` without a map, OTLP options without
       ``--otel``, an invalid upatch name, or with ``--all`` an invalid
       ``map_export`` configuration.

Files and environment
---------------------

- Reads the pinned maps under ``/run/shirudo/bpffs/upatches/``
- Appends to the ``--json`` or ``map_export.json_path`` file
- OTLP and S3: the ``OTEL_EXPORTER_OTLP_*`` and ``AWS_*`` variables (see
  :doc:`/reference/environment`). ``shirudo-map-export.service`` reads
  them from ``/etc/shirudo/map-export.env``

Examples
--------

List the pinned maps of a target without any:

.. code-block:: console

   target# shirudo upatch map
   Pinned maps (0):
     none

Look at a serializer-backed map without taking its records from the
exporter:

.. code-block:: console

   target# shirudo upatch map kernel-obs exec --json --peek

Send one map to a collector:

.. code-block:: console

   target# shirudo upatch map kernel-obs exec --otel --otel-endpoint=https://collector.example:4318 --tenant-id=fleet-eu-1

Related
-------

- :doc:`/operate/run/telemetry`
- :doc:`/reference/formats/otlp`
- :doc:`/reference/formats/map-export`
- :doc:`/upatches/write/maps-arenas-serializers`
- :doc:`/upatches/write/decoders`
- :doc:`upatch-get`
