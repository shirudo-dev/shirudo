..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: Operators

Exposure
========

Every five minutes: which nodes run a vulnerable package or kernel, and
whether an upatch from their tree shields them. Packages come from the SBOM
of the booted image, the kernel from kernel_release, the shield from the
mask and node_ops.

Schema: :src:`tools/backend/sql/50-vulns.sql`

Views, functions and jobs
-------------------------

``kver(release)``
   SQL function (global).

   Leading numbers of a kernel release: '7.4.2-shirudo' → [7, 4, 2]. Arrays
   compare element-wise, so ranges work. A release with no leading number is
   [].

``shirudo.node_vulns_mv``
   refreshable MV, every 5 minutes.

   Joins node_status, latest, sbom_images, sbom_vulns, kernel_vulns,
   tree_ops, upatch_fixes and node_ops into node_vulns. Work is done per
   image, per kernel release and per tree path, then joined to nodes.

``jobs/sbom-scan``
   external job.

   Scans every image in the SBOM store with Trivy and loads sbom_images and
   sbom_vulns.

shirudo.sbom_images
-------------------

.. clickhouse-table:: shirudo.sbom_images
   :kind: ref
   :written-by: :src:`tools/backend/jobs/sbom-scan` (``file://`` or ``s3://`` store, Trivy as
      matcher)
   :row-size: ~300 B (estimate).
   :scale: Images × versions × builds in the SBOM store.
   :reference: negligible
   :bytes: 100000

   One row per image in the SBOM store, with the outcome of its newest scan.

   - Only an image with state ok has findings in sbom_vulns.
   - A node's SBOM is the one with the node's own image_root if present,
     else the newest build of that id and version.

   :image_id: Image name, e.g. fleet-os.
   :image_version: e.g. 2026.11.1.
   :image_root: Verity root. Empty for an image built without verity.
   :sbom_format: From image.json; cyclonedx-json when it names none.
   :sbom_sha256: Hash of the SBOM file. Empty unless state is ok. Joins to sbom_vulns.
   :state: Outcome of reading the SBOM.
   :built_at: Image build time. Breaks ties between builds.
   :db_version: Trivy advisory database version used.
   :scanned_at: When this scan ran.

shirudo.sbom_vulns
------------------

.. clickhouse-table:: shirudo.sbom_vulns
   :kind: ref
   :written-by: :src:`tools/backend/jobs/sbom-scan`
   :row-size: ~80 B (estimate: sorted by SBOM, repeated strings compress).
   :scale: Distinct SBOMs × findings × scans in the last 7 days.
   :reference: 50 × 500 × 7 daily scans: 175k rows ≈ 15 MB
   :bytes: 1.5e+07

   Findings of every scan of an SBOM. An image's current findings are the
   rows whose scanned_at equals its newest scan in sbom_images.

   - Kernel packages (linux-image-\*, kernel, kernel-core) are ignored here:
     the node may run a different kernel than the image ships, so kernel
     findings come from kernel_vulns only.

   :sbom_sha256: Which SBOM.
   :vuln_id: Advisory id, e.g. a CVE.
   :package: Affected package.
   :installed: Installed version.
   :fixed: First fixed version; empty when none exists.
   :severity: As Trivy reports it.
   :scanned_at: Which scan produced the row.

shirudo.kernel_vulns
--------------------

.. clickhouse-table:: shirudo.kernel_vulns
   :kind: ref
   :written-by: the operator
   :row-size: ~60 B (estimate).
   :scale: Affected release ranges of kernel advisories.
   :reference: thousands of rows, negligible
   :bytes: 200000

   Kernel advisories, one row per affected range of releases. Matched
   against each distinct kernel_release with kver().

   :vuln_id: Advisory id.
   :introduced: First affected release, inclusive, e.g. [7, 0].
   :fixed: First fixed release, exclusive. Empty means no end.
   :severity: As the advisory gives it.

shirudo.node_vulns
------------------

.. clickhouse-table:: shirudo.node_vulns
   :kind: ui
   :queried-by: the UI
   :row-size: ~60 B (estimate: sorted by node; repeated strings compress well).
   :scale: Nodes × (findings on their image and kernel + 1). The whole table is
      rewritten every 5 minutes.
   :reference: 10,000 × 500: 5M rows ≈ 300 MB, rewritten every 5 minutes
   :bytes: 3e+08

   One row per node and finding, plus one row with an empty vuln_id for a
   node with none, so a clean node differs from a missing one. This is what
   a UI reads for exposure.

   - A row says where the node is, not where the tree is.
   - A stale scan keeps its findings and sets sbom_stale. It never makes a
     node read clean: a node without findings then reads unknown.
   - With several upatches linked to one advisory, the best exposure wins,
     in enum order.

   :node_id, ak_name, host_name: Node, as in node_status.
   :status, trust: Copied from node_status.
   :image_id, image_version: From the node's newest record.
   :binding: How far the SBOM can be trusted to describe the node. verified:
      image_root matches the SBOM's.
   :sbom_stale: Newest scan is older than sbom_stale_seconds.
   :source: Where the finding came from.
   :vuln_id: Empty for the 'no findings' row.
   :severity, package, installed, fixed: From sbom_vulns, or linux / kernel_release / fixed release for kernel
      findings.
   :exposure: Best first: shielded, shield_pending, shield_module_absent,
      shield_excludes_node, shield_withdrawn, exposed_no_shield, none,
      unknown.
   :upatch_id: Linked upatch the outcome is read from.
   :applied_seq, applied_op: Newest operation of that upatch the node has applied; 0 and empty if
      none.
   :next_seq, next_op: Newest operation of that upatch in the tree. next_seq > applied_seq
      means something is coming.
   :next_shields: The newest operation is an add linked to this advisory.
   :shield_link: Where the advisory link comes from.
   :updated_at: When the row was computed.
