-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- mask_code reads the outcome pair of one operation from a mask: the masks
-- of the example, the 16-operation mask of the record page, and what must
-- not stop a refresh: an index past the mask, a mask that is not base64
-- and no mask.

SELECT mask, arrayMap(i -> mask_code(mask, i), range(count)) AS codes
FROM
(
    SELECT arrayJoin([('QA==', 1), ('gA==', 1), ('VA==', 4), ('qA==', 4), ('WdlZAA==', 16), ('', 1),
                      ('VA==', 6), ('not base64', 4)]) AS vector,
           vector.1 AS mask, vector.2 AS count
);
SELECT mask_code(CAST(NULL AS Nullable(String)), 0);
