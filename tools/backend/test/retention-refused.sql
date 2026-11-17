-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- test/retention-refused.sh has shown what sql/apply-retention.sh refuses
-- and what each run left of the two TTLs. The settings keep what the
-- operator wrote last, applied or not.

SELECT keepalive_retention_seconds, boot_first_retention_seconds FROM shirudo.settings FINAL;
