-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- test/sbom-scan-unreadable.sh loads nothing: the unreadable and the
-- missing store fail before any insert, and the readable empty store
-- inserts no row.

SELECT 'sbom_images', count() FROM shirudo.sbom_images;
