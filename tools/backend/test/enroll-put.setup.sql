-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- One key the backend has a record of, under the host name it claimed,
-- and not enrolled.

INSERT INTO shirudo.nodes (ak_name, node_id, first_seen)
SELECT concat('000b', repeat('a', 64)), argMinState('host-a', toDateTime64('2026-11-01 10:00:00', 3)),
       toDateTime64('2026-11-01 10:00:00', 3);
