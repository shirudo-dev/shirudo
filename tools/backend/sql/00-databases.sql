-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The two databases: otel takes what the collector writes, shirudo holds
-- everything derived from it. Every file under sql/ can be loaded again
-- without changing what is there.

CREATE DATABASE IF NOT EXISTS otel;
CREATE DATABASE IF NOT EXISTS shirudo;
