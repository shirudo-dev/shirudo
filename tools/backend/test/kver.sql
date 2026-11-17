-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- kver() reads the numbers a kernel release starts with and stops at the
-- first character that continues none. A release that starts with no
-- number is empty, and a number UInt32 cannot hold is 0: neither throws.
-- Arrays compare element by element, a prefix before what extends it,
-- which is what a range of kernel_vulns relies on.

SELECT r, kver(r)
FROM (SELECT arrayJoin(['7.4.2', '7.4.2-shirudo', '7.4.0-rc3+', '7.4', '7', '6.12.57+deb13-amd64', '10.0.100.el10',
                        '7.4.2.1', '7..4', '7.4.', '.7.4', '', 'next-20261111', ' 7.4.2', '007.04.02',
                        '7.4294967295.1', '7.4294967296.1', '7.99999999999999999999999.1']) AS r);

SELECT 'in a range from 7.0 to 7.4.5';
SELECT r, kver(r) >= [7, 0] AND kver(r) < [7, 4, 5]
FROM (SELECT arrayJoin(['6.18.9', '7.0.0', '7.0.0-rc1', '7.4.2', '7.4.4-shirudo', '7.4.5', '7.4.10', '7.5.1', '7']) AS r);

SELECT 'from 7.5 on';
SELECT r, kver(r) >= [7, 5]
FROM (SELECT arrayJoin(['7.4.99', '7.5.0', '7.5', '7.10.0']) AS r);
