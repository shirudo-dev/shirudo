-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The schema loads: every object exists with its engine and key, the
-- functions are declared and the settings hold their defaults. A refresh
-- of node_status writes to a table with a name of its own before it
-- swaps it in, which is left out.

SELECT database, name, engine, sorting_key
FROM system.tables
WHERE database IN ('otel', 'shirudo') AND name NOT LIKE '.tmp.%'
ORDER BY database, name;

SELECT name, engine_full
FROM system.tables
WHERE database = 'shirudo' AND name IN ('boot_first', 'keepalive', 'keepalive_latest', 'node_ops', 'node_sets', 'rejected',
                                            'sbom_images', 'sbom_vulns')
ORDER BY name;

SELECT name, type
FROM system.columns
WHERE database = 'shirudo' AND table = 'nodes'
ORDER BY position;

SELECT name, type
FROM system.columns
WHERE database = 'shirudo' AND table = 'node_status'
ORDER BY position;

SELECT name, type
FROM system.columns
WHERE database = 'shirudo' AND table = 'node_vulns'
ORDER BY position;

SELECT name FROM system.functions WHERE name IN ('kver', 'mask_code', 'tpm_quote_check') ORDER BY name;

SELECT * EXCEPT (updated) FROM shirudo.settings FINAL;

-- A changed setting replaces the row.
INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds, boot_first_retention_seconds)
VALUES (3, 6, 4, 7200, 5184000);
SELECT * EXCEPT (updated) FROM shirudo.settings FINAL;
