-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The catalog after test/shields-put.sh: four rows, ssl-fix at 1.0.0 and
-- at 1.1.0 beside xfs-fix and probe, with the digests without "sha256:",
-- the fixes in byte order and the selectors as compact JSON. The refused
-- files loaded nothing.

SELECT reference, id, package, version, manifest_digest, fixes, selector, description
FROM shirudo.shield_catalog FINAL
ORDER BY reference, id;
