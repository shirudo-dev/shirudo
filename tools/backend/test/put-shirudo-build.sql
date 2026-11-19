-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The builds after test/put-shirudo-build.sh: the one given by version_id
-- and the one the binary gave, with the first put's note, and the third
-- from the second put, without one. The refused calls loaded nothing.

SELECT left(version_id, 4), note FROM shirudo.expected_builds FINAL ORDER BY version_id;
