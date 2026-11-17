-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- What jobs/sbom-scan loaded with the real Trivy in
-- test/sbom-scan-trivy.sh, as far as it does not depend on the advisory
-- database: the image is ok and names the database it was scanned with,
-- and every finding is of the image's SBOM and none of a kernel package.

SELECT image_version, state, db_version != '' FROM shirudo.sbom_images FINAL;
SELECT 'findings of another SBOM', countIf(sbom_sha256 != 'fd2407ebf451915ddb23cd4cabd3cee23db62e7f1d7a81c8c3cfb3b1c48596e4')
FROM shirudo.sbom_vulns;
SELECT 'kernel findings', countIf(match(package, '^(linux-image-|kernel$|kernel-core$)'))
FROM shirudo.sbom_vulns;
