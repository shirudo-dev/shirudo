..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Scan the SBOMs
==============

``node_vulns`` takes a node's packages from the SBOM of the image it
booted. :src:`tools/backend/jobs/sbom-scan` reads those SBOMs from the store the image
build pipeline writes them to, has a matcher find the advisories that
affect their packages and writes the outcome to ``sbom_images`` and
``sbom_vulns``. It is POSIX shell around Trivy, the matcher, and
``clickhouse-client``, with :src:`tools/backend/jobs/sbom-rows.py` to read the JSON, so the
host that runs it needs ``python3``, ``clickhouse-client``, ``trivy`` and, for
a store in S3, the AWS command line ``aws``.

.. code-block:: console

   $ trivy image --download-db-only --cache-dir /var/cache/trivy
   $ jobs/sbom-scan --store s3://fleet-sboms --cache-dir /var/cache/trivy
   $ jobs/sbom-scan --store file:///srv/sboms --cache-dir /var/cache/trivy

What it reads
-------------

One directory per image, which the image pipeline writes once and never
changes, itself or through :doc:`sbom-put`; this job never writes it:

.. code-block:: none

   <store>/<image_id>/<image_version>/<image_root or ->/image.json
   <store>/<image_id>/<image_version>/<image_root or ->/sbom.cdx.json

with an ``image.json`` like

.. code-block:: json

   {"image_id": "fleet-os", "image_version": "2026.11.1",
    "image_root": "a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c",
    "sbom_format": "cyclonedx-json",
    "sbom_sha256": "<64 lowercase hex digits, the SHA-256 of sbom.cdx.json>",
    "built_at": "2026-11-02T08:00:00Z"}

The path is the image's key, the same as the keepalive's ``image_id``,
``image_version`` and ``image_root``: a rebuild that keeps its version
has another root and is another image, and an image built without verity
has ``-`` in the path and an empty ``image_root``. ``image_id`` and
``image_version`` are 1 to 255 characters of ``[A-Za-z0-9._~+-]`` that
do not start with a dot, and the root is 64 lowercase hex digits. An
``image.json`` anywhere else in the store is named on standard error and
left out. ``built_at`` is UTC in exactly that form. ``sbom_format``
names the format of the SBOM and so its file: ``cyclonedx-json``, in
``sbom.cdx.json``, is the only one the job reads, and what an
``image.json`` without the key means. Other keys are ignored.

Image states
------------

The first row that applies:

.. list-table::
   :header-rows: 1

   * - ``state``
     - When
   * - ``parse_error``
     - ``image.json`` is not a JSON object, lacks one of the keys above, has one in another form, or names another image than its path. ``sbom_format`` is then ``cyclonedx-json`` and ``built_at`` 0.
   * - ``unsupported_format``
     - ``sbom_format`` names a format the job has no reader for. The job never guesses one from the file.
   * - ``missing``
     - There is no file of that format beside ``image.json``.
   * - ``hash_mismatch``
     - The SHA-256 of the file is not ``sbom_sha256``.
   * - ``parse_error``
     - The format's reader refuses the file. A CycloneDX SBOM must be JSON with ``"bomFormat": "CycloneDX"`` and components that have names; any ``specVersion`` is read.
   * - ``ok``
     - The reader turned the file into its components, and the matcher scanned it.

Only an image whose state is ``ok`` has ``sbom_sha256``, ``db_version``
and findings. The matcher reads a copy of the bytes that were hashed,
not the store again. Each reader is one function in
:src:`tools/backend/jobs/sbom-rows.py` that turns a file into component
rows, beside the name of the format's file: a second format is one more
reader there, and one the matcher reads too. Nothing after the job
depends on the format.

Matcher
-------

For each image that is ``ok`` the job runs ``trivy sbom --format json
--skip-db-update --quiet <copy>``, and ``trivy version --format json``
once, whose ``VulnerabilityDB.UpdatedAt`` becomes ``db_version``, both
with ``--cache-dir`` when it is given. Every vulnerability in the
``Results`` of the report becomes a row of ``sbom_vulns``:

.. list-table::
   :header-rows: 1

   * - ``sbom_vulns``
     - From
   * - ``vuln_id``
     - ``VulnerabilityID``
   * - ``package``
     - ``PkgName``
   * - ``installed``
     - ``InstalledVersion``
   * - ``fixed``
     - ``FixedVersion``, empty when the report has none
   * - ``severity``
     - ``Severity``, ``UNKNOWN`` when the report has none

Findings of the kernel's packages, ``linux-image-*``, ``kernel`` and
``kernel-core``, are left out, since the node may run another kernel
than the image installs, and a row the report gives twice is written
once. Images whose SBOMs are the same bytes share their findings: the
job writes them once per run, for the first of those images, and names
that image on the line of each other one. A report that is not in that
form is refused. Trivy is this job's choice, not the tables': another
matcher takes the place of the command and of that mapping. The job
never updates Trivy's database: update it before a run, as above. Trivy
reads further options from its own ``TRIVY_*`` environment variables.

What it writes
--------------

Every run scans every image again. All rows of a run carry one
``scanned_at``, later than that of any scan before it, and the job
inserts the findings before the rows of ``sbom_images``, which make a
node read them. The last scan of an image is the one ``node_vulns``
reads; the findings of earlier ones leave with the TTL. It prints a line
per image loaded, with its state and why, or the number of its
components and findings.

When something fails
--------------------

An image whose scan fails, or whose report is refused, is named on
standard error and left out of the run, as is an ``image.json`` out of
place: its row stays that of its last scan, which turns stale. The job
loads the rest and exits with status 1. A store it cannot read, a copy
from S3 that fails or a matcher that cannot say its version loads
nothing, with status 1. Wrong usage is status 2.

Connection
----------

As :src:`tools/backend/jobs/tree-ingest`, the job runs
``clickhouse-client`` or the command ``CLICKHOUSE_CLIENT`` names. Its
user needs ``SELECT`` on ``shirudo.sbom_images`` and ``INSERT`` on
``shirudo.sbom_images`` and ``shirudo.sbom_vulns``. For an
``s3://<bucket>[/<prefix>]`` store it runs ``aws s3 cp --recursive`` for
the objects it reads, every one of them for every run, with the
credentials and region of AWS's own environment and configuration;
``S3_CLIENT`` names another command with its options, split at spaces,
for example ``aws --endpoint-url https://s3.example.com`` for an S3
store not at AWS. ``SBOM_STORE``, ``TRIVY`` and ``TRIVY_CACHE_DIR``
stand in for ``--store``, ``--trivy`` and ``--cache-dir``.

When to run it
--------------

Daily, after updating Trivy's database, and more often than
``sbom_stale_seconds`` allows; and, if you like, when the image pipeline
has stored a new image, which is otherwise scanned at the next run:
``sbom-put --scan`` does that. With
``SBOM_STORE`` and ``TRIVY_CACHE_DIR``, which Trivy reads too, in
``/etc/shirudo-backend/sbom-scan.env``:

.. code-block:: ini

   # sbom-scan.service
   [Service]
   Type=oneshot
   EnvironmentFile=/etc/shirudo-backend/sbom-scan.env
   ExecStartPre=/usr/bin/trivy image --download-db-only
   ExecStart=/opt/shirudo-backend/jobs/sbom-scan

   # sbom-scan.timer
   [Timer]
   OnCalendar=daily
   [Install]
   WantedBy=timers.target
