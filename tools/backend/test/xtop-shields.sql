-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- Every upatch of every tree is a row of the shields view;
-- xtop-shields.sh prints the rows.

SELECT 'shields', uniqExact(tree_id, id) FROM shirudo.tree_ops FINAL;
