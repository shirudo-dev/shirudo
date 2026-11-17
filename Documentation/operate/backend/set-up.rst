..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Set up
======

You need a ClickHouse server, the OpenTelemetry Collector Contrib
distribution (``otelcol-contrib``) and ``shirudo-quote-check`` from
shirudo's operator package on the ClickHouse host. Run the commands
from :src:`tools/backend/` of a shirudo checkout.

1. Install the quote checker as the ``tpm_quote_check`` function. Copy
   the declaration beside the server's ``config.xml`` and the program
   into the server's ``user_scripts`` directory, then have the server
   read it:

   .. code-block:: console

      # install -m 0644 clickhouse/tpm_quote_check_function.xml /etc/clickhouse-server/
      # install -m 0755 "$(command -v shirudo-quote-check)" /var/lib/clickhouse/user_scripts/
      $ clickhouse-client --query 'SYSTEM RELOAD FUNCTIONS'

   The server starts up to four checker processes and keeps them. Each
   reads rows of ``attest``, ``sig``, ``ak`` and the body's SHA-256
   separated by tabs, and answers every row with one line of JSON. The
   checker keeps no state and no list of keys: a pass says that the body
   is what this key signed, not that the key lives in a genuine TPM.

2. Load the schema. The function has to exist first, because
   ``shirudo.checked_mv`` names it:

   .. code-block:: console

      $ for file in sql/*.sql; do clickhouse-client <"$file"; done
      $ sql/apply-retention.sh

   Loading it again changes nothing. ``sql/apply-retention.sh`` gives
   ``shirudo.keepalive`` and ``shirudo.boot_first`` the retention that
   ``shirudo.settings`` names (:doc:`maintain`). It runs
   ``clickhouse-client``, or the command given as its arguments:

   .. code-block:: console

      $ sql/apply-retention.sh clickhouse-client --host ch.example.com --secure

3. Run the collector with ``otelcol.yaml``. It reads its TLS certificate
   and key from ``/certs/server.pem`` and ``/certs/server.key`` and
   writes to ``tcp://clickhouse:9000`` as ``default``, unless
   ``OTLP_TLS_CERT``, ``OTLP_TLS_KEY``, ``CLICKHOUSE_ENDPOINT``,
   ``CLICKHOUSE_USER`` and ``CLICKHOUSE_PASSWORD`` say otherwise. The
   collector's user needs ``INSERT`` on ``otel.otel_logs`` and nothing
   else. Targets require TLS 1.3 with a hybrid ML-KEM key exchange, which
   a collector built with Go 1.24 or later offers.

4. Point the targets at the collector, as :doc:`/operate/run/telemetry`
   describes.
