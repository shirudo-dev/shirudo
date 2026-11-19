-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What the --scan of test/sbom-put.sh loaded: the image it stored, with
-- the findings of its SBOM.

SELECT image_id, image_version, image_root, sbom_format, sbom_sha256, state, built_at, db_version
FROM shirudo.sbom_images FINAL
ORDER BY image_id, image_version, image_root;
SELECT sbom_sha256, vuln_id, package FROM shirudo.sbom_vulns ORDER BY vuln_id, package;
