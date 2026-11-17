-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/sbom-scan loaded from the s3:// store in
-- test/sbom-scan-s3.sh: its two images, as from a file:// store, and the
-- findings of the one that has some. The runs it refused added nothing.

SELECT image_id, image_version, image_root, sbom_format, sbom_sha256, state, db_version
FROM shirudo.sbom_images FINAL
ORDER BY image_id, image_version, image_root;
SELECT sbom_sha256, vuln_id, package FROM shirudo.sbom_vulns ORDER BY vuln_id, package;
