..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

Operate
=======

These pages are for the engineers who deploy, run and troubleshoot
shirudo targets in production. Start with the
:doc:`/operate/deploy/deployment-checklist`, which lists every step from
the operator keys to a verified first boot and links the page that does
each one.

On a running target, :doc:`/operate/run/read-status` tells you what the
target reports about itself, and :doc:`/operate/run/attest` gets the same
answer signed by the target's TPM. When something fails, start from the
message in :doc:`/operate/troubleshoot/troubleshooting`. A ``tampered``
refusal or verdict is an incident: follow
:doc:`/operate/troubleshoot/incident-tampered`.

- :doc:`plan/index`: what a target needs and costs, how shirudo scales,
  what runs beside it and how to harden it
- :doc:`deploy/index`: from the checklist through boot integration to an
  initialized target
- :doc:`run/index`: deliver packages, read status, export telemetry and
  attest targets
- :doc:`integrations/index`: send telemetry to ClickHouse,
  Elasticsearch, Grafana and Splunk
- :doc:`backend/index`: check every keepalive's quote and each target's
  state against its upatch tree
- :doc:`maintain/index`: signing keys, upgrades, backup, recovery and
  decommissioning
- :doc:`troubleshoot/index`: failures by symptom, tampered targets and bug
  reports

.. toctree::
   :hidden:

   plan/index
   deploy/index
   run/index
   integrations/index
   backend/index
   maintain/index
   troubleshoot/index
