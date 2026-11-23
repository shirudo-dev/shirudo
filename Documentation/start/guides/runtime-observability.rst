..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Tutorial
:audience: Operators, upatch authors

Observe a target at runtime
===========================

In this tutorial you collect what happens on a running target: which
programs it executes, where it connects, which names it resolves and who
reads its credential files. The ``kernel-obs`` upatch of
:src:`upatches/kernel-obs/` records these in tables inside the kernel,
the target exports the tables over OpenTelemetry every few seconds, and
you query the records in the collector's ClickHouse. Nothing on the
target listens, and no agent runs between exports.

Every hook of ``kernel-obs`` observes. It refuses nothing, so loading it
changes no behavior of the target.

Before you begin
----------------

- A shell that may lock memory, which ``shirudo`` does as it starts:

  .. code-block:: console

     operator$ sudo prlimit --pid $$ --memlock=unlimited:unlimited

  ``ulimit -l`` then prints ``unlimited``. Under a lower limit
  ``shirudo`` stops with ``hardening: cannot lock process memory``, and
  ``make vm`` with ``cannot fingerprint the bundle's own certificate``
  or ``cannot read the version_id of the bundle's shirudo``. The limit
  belongs to the shell: set it in each terminal you run the commands of
  this guide in.
- The local stack and the test VM, started from the root of your
  checkout, the settings of the stack in your operator shell and the
  target enrolled in the backend:

  .. code-block:: console

     operator$ make stack-up && make vm VM_NAME=quickstart
     operator$ . build/test-vm/stack/env
     operator$ make vm-enroll VM_NAME=quickstart

  :doc:`backend` explains these lines. A shell you open later needs the
  second line again.

- ``jq`` on the operator host
- A root shell on the target, in which ``shirudo`` runs the runtime
  binary:

  .. code-block:: console

     operator$ make vm-ssh VM_NAME=quickstart

Publish and deliver kernel-obs
------------------------------

1. Build the package and push it to a namespace of the registry:

   .. code-block:: console

      operator$ mkdir -p build/tutorial
      operator$ tools/put-shields --version 1.0.0 --keys-dir "$KEYS" --catalog build/tutorial/observability.json --new-index oci://127.0.0.1:15444/observability upatches/kernel-obs
      wrote /tmp/shirudo-bpm-build.H0hmLw/0.upatch (insns=40024 sig=4853 data=842568 sections=3 maps=19 progs=35 decoders=9 name=kernel-obs)
      wrote /tmp/shirudo-bpm-build.H0hmLw/0.unload.upatch (insns=1320 sig=4853 data=2832 sections=2 maps=1 progs=1 decoders=0 name=kernel-obs UNLOAD)
      wrote /tmp/shirudo-bpm-build.H0hmLw/1.upatch (insns=1184 sig=4853 data=3208 sections=2 maps=1 progs=1 decoders=0 name=userns-unshare-counter)
      wrote /tmp/shirudo-bpm-build.H0hmLw/1.unload.upatch (insns=1320 sig=4853 data=2832 sections=2 maps=1 progs=1 decoders=0 name=userns-unshare-counter UNLOAD)
      put-shields: pushed oci://127.0.0.1:15444/observability/kernel-obs:1.0.0 sha256:88f955c13ee9c768141f8035c7ebefc7676931ce0dd81fb06bba1d40941a35fb
      shirudo bpm tree append oci://127.0.0.1:15444/observability/kernel-obs:1.0.0 --package-digest sha256:88f955c13ee9c768141f8035c7ebefc7676931ce0dd81fb06bba1d40941a35fb oci://<registry>/<tree> --tree-id <tree-id>

   :src:`tools/put-shields` runs ``shirudo bpm build`` and ``shirudo bpm
   push`` for the package of :src:`upatches/kernel-obs/`, which sign its
   upatches and the namespace's index with the key in ``KEYS``. The
   ``kernel-obs`` upatch holds 35 BPF programs and 9 decoders. A decoder
   is a signed Lua script that turns the bytes of one table into the
   records the target exports, so the meaning of a table ships with the
   upatch that fills it. The last line is the command that appends the
   package to a tree, by its reference and the digest of its manifest.
   Your digest differs.

2. Keep the digest and tell the backend that the package is available:

   .. code-block:: console

      operator$ OBS_DIGEST=$(jq -r '.shields[0].manifest_digest' build/tutorial/observability.json)
      operator$ tools/backend/jobs/shields-put build/tutorial/observability.json
      shields-put: oci://127.0.0.1:15444/observability/kernel-obs:1.0.0 kernel-obs (no advisory)
      shields-put: loaded shields: 1

   The catalog ``put-shields`` wrote holds the ``sha256:`` value its
   command printed after ``--package-digest``.

3. Append the package to the tree:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/observability/kernel-obs:1.0.0 --package-digest "$OBS_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS"
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:50a07b7010b81cee2cadc0ad6fbc4becb78ebd2c4393fe8890b3cd90c1fa3b90

   The tree is a signed list of operations. A tree takes the upatches of
   a package that have an ``[upatches.tree]`` table in the ``Beefile``:
   here ``kernel-obs``, without a selector, so that every target that
   follows the tree loads it. ``userns-unshare-counter``, the second
   upatch of the package, has no such table and stays out.

4. Wait for the target's next sync, at most 10 seconds on the test VM,
   and list its upatches and their maps:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        NAME                      LOADED  TYPE    KIND  PAYLOAD
        kernel-obs                yes     load    bpf   c96d3d59730d5aa1..
      target# shirudo upatch map kernel-obs
      Pinned maps (9):
        UPATCH                 MAP              TYPE               ENTRIES
        kernel-obs             watch_stat       percpu_array       max=1  (per-cpu)
        kernel-obs             file             array              max=1
        kernel-obs             priv             array              max=1
        kernel-obs             dns              array              max=1
        kernel-obs             watch            array              max=1
        kernel-obs             listen           array              max=1
        kernel-obs             socket           array              max=1
        kernel-obs             net              array              max=1
        kernel-obs             exec             array              max=1

   Each map but ``watch_stat`` stands for one table in the upatch's BPF
   arena. ``shirudo-map-export.timer`` runs ``shirudo upatch map --all``
   every 5 seconds, which drains every table through its serializer and
   decoder and sends the records to the collector.

5. Load the tree into the backend and read the target's checks:

   .. code-block:: console

      operator$ tools/backend/jobs/tree-ingest --shirudo "$PWD/shirudo" --cert "$KEYS/cert.der" "$TREE"
      tree-ingest: loaded local-tree generation 1 (operations: 1, fixes: 0)
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SYSTEM REFRESH VIEW shirudo.node_status_mv; SYSTEM WAIT VIEW shirudo.node_status_mv"
      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT arrayJoin(log) FROM shirudo.node_status"
      1 signed: pass, enrolled, 0 rejected in the last hour
      2 fresh: pass, last record 10 s ago
      3 reported: FAIL, verdict ok, cond 0x1555, flags 0, tamper +8, build 59400f7e
      4 chain: pass, root a2e481e0
      5 head: pass, seq 1 of 1, generation 1
      6 set: pass, 1 loaded
      7 peers: no peers, 1 in group

   Checks 4 to 6 say that the target is at the head of the tree and runs
   the one upatch it leaves loaded. Check 3 fails here because the
   target's tamper counters rose after its first record;
   :doc:`/operate/backend/status` says how each check reads a record.

Cause events and read their records
-----------------------------------

1. Resolve a name, open a TCP connection and read a credential file on
   the target:

   .. code-block:: console

      target# getent hosts example.com
      2606:4700:10::ac42:93f3 example.com
      2606:4700:10::6814:179a example.com
      target# curl --silent --output /dev/null http://10.0.2.2:18124/ping
      target# head -c 1 /etc/shadow >/dev/null

2. Wait for the next export and count what the collector holds for each
   table:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT LogAttributes['shirudo.map.name'] AS map, count() AS snapshots, sum(length(JSONExtractArrayRaw(Body, 'records'))) AS records FROM shirudo.otel_logs WHERE EventName = 'shirudo.bpf.map.snapshot' GROUP BY map ORDER BY map FORMAT PrettyCompactMonoBlock"
         ┌─map────┬─snapshots─┬─records─┐
      1. │ dns    │         6 │      12 │
      2. │ exec   │         6 │     438 │
      3. │ file   │         6 │      19 │
      4. │ listen │         6 │       0 │
      5. │ net    │         6 │      45 │
      6. │ priv   │         6 │     262 │
      7. │ socket │         6 │    1098 │
      8. │ watch  │         6 │       0 │
         └────────┴───────────┴─────────┘

   Each export of a table is one OpenTelemetry log record, a snapshot,
   whose body is a JSON document with the records of that interval. Most
   of them come from the target's own services and from your shell
   session. Your counts differ.

3. Find the programs you ran:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT JSONExtractString(r, 'path') AS path, JSONExtractUInt(r, 'uid') AS uid, JSONExtractUInt(r, 'pid') AS pid FROM shirudo.otel_logs ARRAY JOIN JSONExtractArrayRaw(Body, 'records') AS r WHERE LogAttributes['shirudo.map.name'] = 'exec' AND match(path, '/(getent|curl|head)\$') ORDER BY pid FORMAT PrettyCompactMonoBlock"
         ┌─path──────────────────────────────┬─uid─┬──pid─┐
      1. │ /usr/bin/getent                   │   0 │ 3304 │
      2. │ /usr/bin/curl                     │   0 │ 3305 │
      3. │ /usr/lib/cargo/bin/coreutils/head │   0 │ 3306 │
         └───────────────────────────────────┴─────┴──────┘

   The ``exec`` table has a record for each program a task executed,
   with its path, its user and the program that called it. The path is
   that of the file the kernel ran: ``/usr/bin/head`` is a symbolic link
   on the test VM, and the record names what it points to.

4. Find the connection ``curl`` opened:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT JSONExtractString(r, 'address') AS address, JSONExtractUInt(r, 'port') AS port, JSONExtractString(r, 'proto') AS proto, JSONExtractString(r, 'role') AS role FROM shirudo.otel_logs ARRAY JOIN JSONExtractArrayRaw(Body, 'records') AS r WHERE LogAttributes['shirudo.map.name'] = 'net' AND port = 18124 FORMAT PrettyCompactMonoBlock"
         ┌─address──┬──port─┬─proto─┬─role──────┐
      1. │ 10.0.2.2 │ 18124 │ tcp   │ initiator │
         └──────────┴───────┴───────┴───────────┘

   The ``net`` table has one record per peer, with the bytes and packets
   each way and the executable that owns the socket.

5. Find the name you resolved:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT DISTINCT JSONExtractString(r, 'names', 1, 'name') AS name, JSONExtractString(r, 'address') AS address FROM shirudo.otel_logs ARRAY JOIN JSONExtractArrayRaw(Body, 'records') AS r WHERE LogAttributes['shirudo.map.name'] = 'dns' AND name = 'example.com' FORMAT PrettyCompactMonoBlock"
         ┌─name────────┬─address─────────────────────────────────┐
      1. │ example.com │ 2606:4700:0010:0000:0000:0000:ac42:93f3 │
      2. │ example.com │ 2606:4700:0010:0000:0000:0000:6814:179a │
         └─────────────┴─────────────────────────────────────────┘

   The ``dns`` table keeps the addresses of DNS answers with the names
   that resolved to them, so that a connection to an address can be read
   as a connection to a name.

6. Find the read of the credential file:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT JSONExtractString(r, 'path') AS path, JSONExtractString(r, 'mode') AS mode, JSONExtractUInt(r, 'pid') AS pid FROM shirudo.otel_logs ARRAY JOIN JSONExtractArrayRaw(Body, 'records') AS r WHERE LogAttributes['shirudo.map.name'] = 'file' AND path = '/etc/shadow' ORDER BY Timestamp DESC, pid DESC LIMIT 1 FORMAT PrettyCompactMonoBlock"
         ┌─path────────┬─mode─┬──pid─┐
      1. │ /etc/shadow │ r    │ 3306 │
         └─────────────┴──────┴──────┘

   The ``file`` table records opens of the credential and persistence
   files that :src:`upatches/kernel-obs/file-watch.list` names. The
   process is the ``head`` of the step before.

7. Read the counter the upatch exports as a metric:

   .. code-block:: console

      operator$ docker exec -i shirudo-dev-clickhouse clickhouse-client --query "SELECT MetricName, Attributes['outcome'] AS outcome, max(Value) AS value FROM shirudo.otel_metrics_sum GROUP BY MetricName, outcome ORDER BY outcome FORMAT PrettyCompactMonoBlock"
         ┌─MetricName────────────────┬─outcome─┬─value─┐
      1. │ kernel_obs.watch_attempts │ checked │   100 │
      2. │ kernel_obs.watch_attempts │ matched │     0 │
         └───────────────────────────┴─────────┴───────┘

   ``watch_stat`` counts the connections checked against the watched
   destinations of :src:`upatches/kernel-obs/watch.list`. Its decoder
   exports it as an OpenTelemetry sum, where the tables go out as log
   records.

Stop observing
--------------

1. Append a delete for the package:

   .. code-block:: console

      operator$ shirudo bpm tree append oci://127.0.0.1:15444/observability/kernel-obs:1.0.0 --package-digest "$OBS_DIGEST" "$TREE" --tree-id local-tree --keys-dir "$KEYS" --op delete
      oci://127.0.0.1:15444/shirudo/local-tree:stable sha256:db6416ab39111b60d222c51ccd4416bfde1ed0908edfc7516e25f7a01ee32cce

2. After the next sync, check that the upatch and its maps are gone:

   .. code-block:: console

      target# shirudo upatch list
      Archived upatches (/var/lib/shirudo/upatches):
        none
      target# shirudo upatch map
      Pinned maps (0):
        none

   The records already exported stay in the collector's tables.

Tear down
---------

The guides share the stack, the VM and the tree: skip this section to
go on to another one.

1. Remove the VM, the stack and the files of this guide:

   .. code-block:: console

      operator$ make vm-stop VM_NAME=quickstart
      operator$ make vm-clean VM_NAME=quickstart
      operator$ make stack-down
      operator$ rm build/tutorial/observability.json

   Stopping the VM ends the target shell. The VM's disk and TPM state,
   the registry with the tree in it, the backend's tables and the CA
   are gone. The first lines of this guide start again from nothing.

Next steps
----------

- :doc:`/upatches/learn/examples` describes every table of
  ``kernel-obs`` and its records.
- :doc:`/operate/run/telemetry` sets the collector, its TLS and the
  export interval on a real target, and says what to alert on.
- :doc:`/operate/integrations/index` has collector recipes for
  ClickHouse, Elasticsearch, Grafana and Splunk.
- :doc:`/upatches/write/maps-arenas-serializers` and
  :doc:`/upatches/write/decoders` explain how a upatch of your own
  exports its state.
- :doc:`live-patching` and :doc:`system-hardening` use the same tree
  for shields and for a sandbox.
