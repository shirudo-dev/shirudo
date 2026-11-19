..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: How-to
:audience: Operators

Store an image's SBOM
=====================

:doc:`sbom-scan` reads the SBOMs from a store, one directory per image.
An image pipeline that does not write that layout itself hands each
image's SBOM to :src:`tools/backend/jobs/sbom-put`, which checks it and
writes the image's directory. It is POSIX shell, with
:src:`tools/backend/jobs/sbom-rows.py` to read the SBOM, so the host that
runs it needs ``python3`` and, for a store in S3, the AWS command line
``aws``; with ``--scan``, what :doc:`sbom-scan` needs too.

1. Build the image and its CycloneDX JSON SBOM.
2. Store it under the key the image's nodes report in their keepalive,
   its ``image_id``, ``image_version`` and, for an image with verity,
   ``image_root``:

   .. code-block:: console

      $ jobs/sbom-put --store s3://fleet-sboms --image-id fleet-os \
          --image-version 2026.11.1 \
          --image-root a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c \
          --built-at 2026-11-02T08:00:00Z sbom.cdx.json
      sbom-put: fleet-os/2026.11.1/a3c3f1b0e4c2d7f09e3b6b2a8b1d5e7c4f6a9d0b2c8e1f3a5b7d9c0e2f4a6b8c: stored, sha256 fd2407ebf451915ddb23cd4cabd3cee23db62e7f1d7a81c8c3cfb3b1c48596e4, components: 4

3. Scan it now, rather than at the next scheduled run of
   :doc:`sbom-scan`, by adding ``--scan``, which runs that job over the
   whole store once the image is in it.

Options
-------

.. list-table::
   :header-rows: 1

   * - Option
     - Value
   * - ``--store <url>``
     - ``file://<directory>`` or ``s3://<bucket>[/<prefix>]``, the store
       :doc:`sbom-scan` reads; ``SBOM_STORE`` in its place.
   * - ``--image-id <id>``, ``--image-version <version>``
     - The image's id and version: 1 to 255 characters of
       ``[A-Za-z0-9._~+-]`` that do not start with a dot.
   * - ``--image-root <root>``
     - The root hash of the image's verity tree, 64 lowercase hex
       digits. Left out or empty for an image built without verity,
       stored under ``-``.
   * - ``--built-at <time>``
     - When the image was built, UTC as ``YYYY-MM-DDThh:mm:ssZ``. Default:
       now.
   * - ``--scan``
     - Run :src:`tools/backend/jobs/sbom-scan` over the store afterwards,
       which reads its own variables, and exit with its status.

What it writes
--------------

The image's directory, as :doc:`sbom-scan` reads it: the SBOM as
``sbom.cdx.json``, byte for byte, then an ``image.json`` naming the key,
``cyclonedx-json``, the SBOM's SHA-256 and the build time. ``image.json``
goes last and, in a ``file://`` store, each file is renamed into place,
so a scan running meanwhile sees the image whole or not at all.

The SBOM is checked as the scan would check it before anything is
written: it must be JSON with ``"bomFormat": "CycloneDX"`` and components
that have names. A key out of form, a time out of form, or an SBOM the
scan would refuse leaves the store as it was, with status 1.

The store is written once. An image already in it with the same SBOM, by
SHA-256, is left as it is, and the job says so and exits with status 0,
so a pipeline can run it again. One with another SBOM is refused with
status 1: a rebuild that changes the SBOM is a new version, or a new
root.

Exit status
-----------

0 when the image is in the store, and was scanned with ``--scan``; 1
when the image was refused, could not be read or written, or the scan
failed; 2 for wrong usage.

Connection
----------

For an ``s3://`` store it runs ``aws s3 cp``, once with ``--recursive``
to read the image's ``image.json`` if there is one and once per file it
writes, with the credentials and region of AWS's own environment and
configuration. ``S3_CLIENT`` names another command with its options,
split at spaces, as for :doc:`sbom-scan`. Its user needs to read and
write the store's objects.
