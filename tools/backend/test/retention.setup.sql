-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The settings test/retention.sql wants in place when the runner applies
-- the retention: two minutes instead of the default hour for
-- shirudo.keepalive, sixty days instead of the default thirty for
-- shirudo.boot_first.

INSERT INTO shirudo.settings (stale_seconds, stuck_seconds, window, keepalive_retention_seconds,
                              boot_first_retention_seconds)
VALUES (180, 3600, 512, 120, 5184000);
