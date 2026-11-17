..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Integrations
============

Send what targets export into the tools you already run. These pages
are do-it-yourself examples to get started from, not integrations that
shirudo ships or maintains. Each one gives a collector configuration for
one backend, queries that show the records arrive, and alerts for a
target that goes silent, reports a verdict other than ``ok`` or counts
tamper attempts. Adapt them to your deployment.

Splunk and Elastic Security are SIEMs, ClickHouse keeps records for
analysis in SQL, and Grafana charts them from Loki and Prometheus.
:doc:`/operate/backend/index` builds on ClickHouse to check every
keepalive's quote and each target's state against its upatch tree.

Targets speak OTLP over HTTP with JSON bodies and TLS 1.3 with a hybrid
post-quantum key exchange, and nothing else. Each page puts an
OpenTelemetry Collector between the targets and one backend: the
collector accepts the targets' requests, batches and retries, and speaks
the backend's own protocol over ordinary TLS, so the backend needs no
post-quantum support.

.. toctree::
   :titlesonly:

   clickhouse
   elasticsearch
   grafana
   splunk

:doc:`/concepts/background/siem-export` explains how the records reach a
backend and what to build on them.
