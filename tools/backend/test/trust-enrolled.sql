-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo
--
-- The operator raises a key to enrolled with one row in shirudo.nodes:
-- before the node's first record, as from a builder's records, or after
-- it, as after credential activation. The row changes neither the
-- node's name nor when it was first seen, a later row cannot lower it,
-- and latest and node_status carry it without it touching status. A key
-- enrolled but never seen is in no view of the nodes' records, and one
-- never enrolled stays untrusted.

INSERT INTO shirudo.nodes (ak_name, trust) VALUES ('000baa', 'enrolled');
INSERT INTO shirudo.nodes (ak_name, trust) VALUES ('000bcc', 'enrolled');

INSERT INTO shirudo.checked (host_name, quote, body, ok, ak_name, ak_public, reset_count, clock) VALUES
('edge-01', 'q1', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":null,"kernel_release":"7.4.2","image_id":null,"image_version":null,"image_root":null,"verdict":"init-pending","cond":5465,"flags":8,"tamper":null,"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","count":0,"not_ok":0}', 1, '000baa', 'QUtB', 2, 500),
('core-01', 'q2', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":null,"kernel_release":"7.4.2","image_id":null,"image_version":null,"image_root":null,"verdict":"init-pending","cond":5465,"flags":8,"tamper":null,"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","count":0,"not_ok":0}', 1, '000bbb', 'QUtC', 2, 500),
('lab-01', 'q3', '{"schema":"shirudo.keepalive/1","boot_id":"9a6f14ea-0cc2-45e1-8e23-7b887120cf54","version_id":"d6d918ad22ff597579e6678bef75adca84d30f9661e0b7bbdbf534eebc138c1f","config_root":null,"kernel_release":"7.4.2","image_id":null,"image_version":null,"image_root":null,"verdict":"init-pending","cond":5465,"flags":8,"tamper":null,"tree_id":null,"generation":null,"base_seq":null,"last_seq":null,"base_root":null,"projection_root":null,"mask":null,"set_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","count":0,"not_ok":0}', 1, '000bdd', 'QUtD', 2, 500);

INSERT INTO shirudo.nodes (ak_name, trust) VALUES ('000bbb', 'enrolled');
INSERT INTO shirudo.nodes (ak_name, trust) VALUES ('000baa', 'untrusted');

SELECT 'an enrollment row changes only trust';
SELECT ak_name, max(ak_public), argMinMerge(node_id), isNull(min(first_seen)), max(trust)
FROM shirudo.nodes GROUP BY ak_name ORDER BY ak_name;

SELECT 'latest carries trust';
SELECT ak_name, node_id, trust FROM shirudo.latest ORDER BY ak_name;

SYSTEM REFRESH VIEW shirudo.node_status_mv;
SYSTEM WAIT VIEW shirudo.node_status_mv;

SELECT 'node_status carries trust beside status';
SELECT ak_name, status, trust, failed_check, log[1] FROM shirudo.node_status ORDER BY ak_name;
